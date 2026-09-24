use super::*;
use consensus::SequencerEngine;
use ports::ConsensusEngine;
use primitives::Address;

/// Test executor with unsigned envelopes admitted — most tests
/// submit unsigned envelopes built by `build_tx`. The policy is
/// set explicitly at every construction so the `Reject` default
/// exercised by production wiring stays honest.
fn test_executor(max_mempool_entries: usize) -> Executor {
    Executor::new(max_mempool_entries).with_unsigned_tx_policy(UnsignedTxPolicy::Allow)
}

/// [`test_executor`] with explicit sizing — same reasoning.
fn test_executor_with_config(mempool: usize, threshold: usize) -> Executor {
    Executor::with_config(mempool, threshold).with_unsigned_tx_policy(UnsignedTxPolicy::Allow)
}

/// A trivial test module that counts messages.
struct CounterModule {
    /// Dispatch id — parametrized so snapshot tests can register
    /// two independent counters.
    id: u8,
    /// The snapshot-entry key this counter's blob lives under.
    key: Hash,
    count: Mutex<u64>,
}

impl CounterModule {
    fn new() -> Self {
        Self { id: 1, key: Hash([0xEE; 32]), count: Mutex::new(0) }
    }

    /// A second counter for multi-module strict-import tests —
    /// distinct dispatch id and snapshot key.
    fn other() -> Self {
        Self { id: 2, key: Hash([0xEF; 32]), count: Mutex::new(0) }
    }
}

impl Module for CounterModule {
    fn name(&self) -> &'static str {
        "counter"
    }
    fn id(&self) -> u8 {
        self.id
    }

    fn begin_block(&self, _height: Height) {}

    fn handle(&self, _ctx: &TxContext, _msg: &[u8]) -> Result<Vec<Event>, ExecError> {
        let mut c = primitives::sync::lock_state(&self.count);
        *c += 1;
        Ok(vec![Event { module: "counter", kind: "increment", data: vec![] }])
    }

    fn end_block(&self, _height: Height) -> Vec<Event> {
        Vec::new()
    }

    fn state_root(&self) -> Hash {
        let c = *primitives::sync::lock_state(&self.count);
        let byte = u8::try_from(c).unwrap_or(0xff);
        Hash([byte; 32])
    }

    // The counter is committed state: export/import/inspect it
    // so strict snapshot verification exercises the real path.
    fn export_state(&self) -> Option<storage::Snapshot> {
        let c = *primitives::sync::lock_state(&self.count);
        Some(storage::Snapshot { height: 0, entries: vec![(self.key, c.to_le_bytes().to_vec())] })
    }

    fn inspect_state(&self, snapshot: &storage::Snapshot) -> Result<Hash, storage::SnapshotError> {
        let c = self.decode_count(snapshot)?;
        let byte = u8::try_from(c).unwrap_or(0xff);
        Ok(Hash([byte; 32]))
    }

    fn import_state(&self, snapshot: &storage::Snapshot) -> Result<(), storage::SnapshotError> {
        let c = self.decode_count(snapshot)?;
        *primitives::sync::lock_state(&self.count) = c;
        Ok(())
    }
}

impl CounterModule {
    /// The snapshot payload is exactly one entry under our key:
    /// the counter as `u64` LE.
    fn decode_count(&self, snapshot: &storage::Snapshot) -> Result<u64, storage::SnapshotError> {
        if snapshot.entries.len() != 1 || snapshot.entries[0].0 != self.key {
            return Err(storage::SnapshotError::Malformed);
        }
        let bytes: [u8; 8] = snapshot.entries[0]
            .1
            .as_slice()
            .try_into()
            .map_err(|_| storage::SnapshotError::Malformed)?;
        Ok(u64::from_le_bytes(bytes))
    }
}

fn make_tx(module_id: u8, payload: &[u8]) -> TxBytes {
    make_tx_with_nonce(module_id, payload, 0)
}

fn make_tx_with_nonce(module_id: u8, payload: &[u8], nonce: u64) -> TxBytes {
    // Build a tx in the mempool's v0 format:
    // [sender: 20B][nonce: 8B LE][fee: 8B LE][module_id: 1B][payload].
    let sender = Address([0u8; 20]);
    let fee = 100u64;
    let mut bytes = Vec::with_capacity(36 + 1 + payload.len());
    bytes.extend_from_slice(&sender.0);
    bytes.extend_from_slice(&nonce.to_le_bytes());
    bytes.extend_from_slice(&fee.to_le_bytes());
    bytes.push(module_id);
    bytes.extend_from_slice(payload);
    TxBytes::new(bytes)
}

#[test]
fn executor_executes_block_and_produces_state_root() {
    let mut executor = test_executor(100);
    executor.register_module(Arc::new(CounterModule::new()));

    // Submit a tx to the executor's mempool (via AppInterface).
    let tx = make_tx(1, &[42]);
    executor.ingest_tx(tx);

    // Prepare a proposal.
    let budget = types::BlockBudget { max_bytes: 1 << 20, max_gas: 1 << 30 };
    let proposal = executor.prepare_proposal(&budget);
    assert_eq!(proposal.txs.len(), 1);

    // Finalize the block.
    let block = FinalizedBlock {
        context: types::BlockContext::default(),
        height: Height::new(0),
        txs: proposal.txs,
        signers: Vec::new(),
    };
    let ack = executor.finalize_block(&block);
    assert_eq!(ack.height, Height::new(0));

    // The state root should be non-zero (the counter incremented).
    let attestation = executor.attest_state(Height::new(0)).expect("executed");
    assert_ne!(attestation.root, Hash::ZERO);
}

#[test]
fn snapshot_root_matches_block_root() {
    // C8: ONE canonical state-root definition. The root stored
    // at finalize must equal the snapshot's recomputed root —
    // both are `H(module_roots || nonce_root)`. Before the fix
    // `execute_block` hashed module roots alone while
    // `export_snapshot` appended the nonce root: two different
    // commitments for the same state.
    let mut executor = test_executor(100);
    executor.register_module(Arc::new(CounterModule::new()));
    executor.ingest_tx(make_tx(1, &[42]));
    let budget = types::BlockBudget { max_bytes: 1 << 20, max_gas: 1 << 30 };
    let proposal = executor.prepare_proposal(&budget);
    let block = FinalizedBlock {
        context: types::BlockContext::default(),
        height: Height::new(0),
        txs: proposal.txs,
        signers: Vec::new(),
    };
    executor.finalize_block(&block);
    let block_root = executor.state_root_at(0);
    let snapshot = executor.export_snapshot();
    assert_eq!(
        snapshot.state_root, block_root,
        "snapshot and block must share one canonical root definition"
    );
}

#[test]
fn executor_with_sequencer_engine_end_to_end() {
    // Wire the executor behind a SequencerEngine and run the full
    // OAI flow: submit → propose → finalize → attest.
    let mut executor = test_executor(100);
    executor.register_module(Arc::new(CounterModule::new()));

    // Wrap in Arc for the engine.
    let app: Arc<dyn AppInterface> = Arc::new(executor);
    let mut engine = SequencerEngine::new(app);

    // Submit a tx through the engine.
    let tx = make_tx(1, &[1]);
    engine.submit_tx(tx);
    engine.run_until_idle();

    // The engine should have finalized a block.
    assert!(engine.finalized_height().is_some());

    // The state root should be non-zero.
    let app = engine.app();
    let attestation = app.attest_state(Height::new(0)).expect("executed");
    assert_ne!(attestation.root, Hash::ZERO, "state root should be non-zero after execution");
}

#[test]
fn executor_skips_unknown_module() {
    let mut executor = test_executor(100);
    executor.register_module(Arc::new(CounterModule::new()));

    // Submit a tx for an unregistered module (ID 99).
    let tx = make_tx(99, &[1]);
    executor.ingest_tx(tx);

    let budget = types::BlockBudget { max_bytes: 1 << 20, max_gas: 1 << 30 };
    let proposal = executor.prepare_proposal(&budget);
    let block = FinalizedBlock {
        context: types::BlockContext::default(),
        height: Height::new(0),
        txs: proposal.txs,
        signers: Vec::new(),
    };
    executor.finalize_block(&block);

    // The unknown module's tx should be silently skipped.
    // The counter module should not have been called.
    let attestation = executor.attest_state(Height::new(0)).expect("executed");
    // State root is the hash of the counter's state root (0).
    assert_ne!(attestation.root, Hash::ZERO, "state root should reflect counter=0");
}

#[test]
fn executor_multiple_blocks_state_advances() {
    let mut executor = test_executor(100);
    let counter = Arc::new(CounterModule::new());
    executor.register_module(counter.clone());

    // Execute 3 blocks, each with 1 tx. Each tx must use an
    // incrementing nonce — the executor now enforces per-account
    // nonce ordering (H4/H5 fix).
    for h in 0..3u64 {
        let h_byte = u8::try_from(h).unwrap_or(0xff);
        let tx = make_tx_with_nonce(1, &[h_byte], h);
        executor.ingest_tx(tx);
        let budget = types::BlockBudget { max_bytes: 1 << 20, max_gas: 1 << 30 };
        let proposal = executor.prepare_proposal(&budget);
        let block = FinalizedBlock {
            context: types::BlockContext::default(),
            height: Height::new(h),
            txs: proposal.txs,
            signers: Vec::new(),
        };
        executor.finalize_block(&block);
    }

    // The counter should have been called 3 times.
    let count = *primitives::sync::lock_state(&counter.count);
    assert_eq!(count, 3, "counter should have been incremented 3 times");

    // Each block should have a different state root.
    let root0 = executor.attest_state(Height::new(0)).expect("executed").root;
    let root1 = executor.attest_state(Height::new(1)).expect("executed").root;
    let root2 = executor.attest_state(Height::new(2)).expect("executed").root;
    assert_ne!(root0, root1, "state roots should differ across blocks");
    assert_ne!(root1, root2, "state roots should differ across blocks");
}

/// A minimal fee-collector module: records how much it charged.
struct FeeCollector {
    charged: Mutex<u64>,
}

impl Module for FeeCollector {
    fn id(&self) -> u8 {
        9
    }
    fn name(&self) -> &'static str {
        "feecollector"
    }
    fn begin_block(&self, _height: Height) {}
    fn handle(&self, _ctx: &TxContext, _msg: &[u8]) -> Result<Vec<Event>, ExecError> {
        Ok(vec![])
    }
    fn end_block(&self, _height: Height) -> Vec<Event> {
        Vec::new()
    }
    fn state_root(&self) -> Hash {
        Hash::ZERO
    }
    fn charge_fee(&self, ctx: &TxContext) -> Result<(), ExecError> {
        *primitives::sync::lock_state(&self.charged) += ctx.fee;
        Ok(())
    }
}

/// Build a tx with an explicit fee (defaults differ from
/// `make_tx`'s fixed 100).
fn make_tx_with_fee_and_sender(
    module_id: u8,
    payload: &[u8],
    nonce: u64,
    fee: u64,
    sender_byte: u8,
) -> TxBytes {
    let sender = Address([sender_byte; 20]);
    let mut bytes = Vec::with_capacity(36 + 1 + payload.len());
    bytes.extend_from_slice(&sender.0);
    bytes.extend_from_slice(&nonce.to_le_bytes());
    bytes.extend_from_slice(&fee.to_le_bytes());
    bytes.push(module_id);
    bytes.extend_from_slice(payload);
    TxBytes::new(bytes)
}

fn make_tx_with_fee(module_id: u8, payload: &[u8], nonce: u64, fee: u64) -> TxBytes {
    make_tx_with_fee_and_sender(module_id, payload, nonce, fee, 0)
}

/// Regression test: txs routed to a module that never implements
/// `charge_fee` must still pay — through the configured fee
/// collector. Before the fix, the charge was dispatched to the
/// *target* module, whose default no-op meant only self-funded
/// txs ever paid a fee.
#[test]
fn fee_module_charges_other_module_txs() {
    let mut executor = test_executor(100);
    let counter = Arc::new(CounterModule::new());
    let collector = Arc::new(FeeCollector { charged: Mutex::new(0) });
    executor.register_module(counter.clone());
    executor.register_module(collector.clone());
    executor.set_fee_module(9);

    executor.ingest_tx(make_tx_with_fee(1, &[1], 0, 50));
    let budget = types::BlockBudget { max_bytes: 1 << 20, max_gas: 1 << 30 };
    let proposal = executor.prepare_proposal(&budget);
    executor.finalize_block(&FinalizedBlock {
        context: types::BlockContext::default(),
        height: Height::new(0),
        txs: proposal.txs,
        signers: Vec::new(),
    });

    assert_eq!(
        *primitives::sync::lock_state(&collector.charged),
        50,
        "the counter tx's fee must be charged through the collector"
    );
    assert_eq!(
        *primitives::sync::lock_state(&counter.count),
        1,
        "the tx must still execute after paying"
    );
}

/// Regression test: `min_fee` rejects txs whose declared fee is
/// below the floor — the envelope's fee field is
/// sender-controlled, so without a floor every tx could declare 0.
#[test]
fn min_fee_floor_skips_underpaying_txs() {
    let mut executor = test_executor(100).with_min_fee(50);
    let counter = Arc::new(CounterModule::new());
    let collector = Arc::new(FeeCollector { charged: Mutex::new(0) });
    executor.register_module(counter.clone());
    executor.register_module(collector.clone());
    executor.set_fee_module(9);

    // fee=10 < min_fee=50 → skipped (never executed, nonce not
    // advanced). fee=100 ≥ 50 → charged and executed. Different
    // senders: a skipped tx doesn't advance its sender's nonce,
    // so a same-sender follow-up would also be nonce-skipped.
    executor.ingest_tx(make_tx_with_fee_and_sender(1, &[1], 0, 10, 7));
    executor.ingest_tx(make_tx_with_fee_and_sender(1, &[1], 0, 100, 8));
    let budget = types::BlockBudget { max_bytes: 1 << 20, max_gas: 1 << 30 };
    let proposal = executor.prepare_proposal(&budget);
    executor.finalize_block(&FinalizedBlock {
        context: types::BlockContext::default(),
        height: Height::new(0),
        txs: proposal.txs,
        signers: Vec::new(),
    });

    assert_eq!(
        *primitives::sync::lock_state(&counter.count),
        1,
        "only the adequately-paid tx executes"
    );
    assert_eq!(
        *primitives::sync::lock_state(&collector.charged),
        100,
        "only the 100-fee tx is charged"
    );
}

/// A shared-ledger fee collector: `charge_fee` debits the
/// sender's balance, so fee affordability is observable and a
/// drain can make a charge fail.
struct LedgerFeeModule {
    balances: Mutex<HashMap<primitives::Address, u64>>,
    charged_total: Mutex<u64>,
}

impl Module for LedgerFeeModule {
    fn id(&self) -> u8 {
        9
    }
    fn name(&self) -> &'static str {
        "ledgerfee"
    }
    fn begin_block(&self, _height: Height) {}
    fn handle(&self, _ctx: &TxContext, _msg: &[u8]) -> Result<Vec<Event>, ExecError> {
        Ok(vec![])
    }
    fn end_block(&self, _height: Height) -> Vec<Event> {
        Vec::new()
    }
    fn state_root(&self) -> Hash {
        Hash::ZERO
    }
    fn charge_fee(&self, ctx: &TxContext) -> Result<(), ExecError> {
        let mut balances = primitives::sync::lock_state(&self.balances);
        let balance = balances.entry(ctx.sender).or_insert(0);
        if *balance < ctx.fee {
            return Err(ExecError::ModuleRejected("insufficient fee balance".to_string()));
        }
        *balance -= ctx.fee;
        *primitives::sync::lock_state(&self.charged_total) += ctx.fee;
        Ok(())
    }
}

/// A module whose `handle` zeroes a target ledger account — the
/// earlier same-run effect that must be visible to the next
/// tx's fee charge under sequential semantics.
struct DrainModule {
    ledger: Arc<LedgerFeeModule>,
    calls: Mutex<u64>,
}

impl Module for DrainModule {
    fn id(&self) -> u8 {
        1
    }
    fn name(&self) -> &'static str {
        "drain"
    }
    fn begin_block(&self, _height: Height) {}
    fn handle(&self, _ctx: &TxContext, msg: &[u8]) -> Result<Vec<Event>, ExecError> {
        if msg.len() >= 20 {
            let victim = primitives::Address(<[u8; 20]>::try_from(&msg[..20]).unwrap_or([0u8; 20]));
            primitives::sync::lock_state(&self.ledger.balances).insert(victim, 0);
        }
        *primitives::sync::lock_state(&self.calls) += 1;
        Ok(vec![])
    }
    fn end_block(&self, _height: Height) -> Vec<Event> {
        Vec::new()
    }
    fn state_root(&self) -> Hash {
        Hash::ZERO
    }
}

/// Regression test for the within-run fee residual: under
/// sequential semantics a tx's fee charge must observe the
/// ledger effects of earlier same-run txs. Sender S2 can afford
/// its fee at run start, but an earlier same-run tx drains S2's
/// balance — the charge must then fail and the tx must be
/// skipped `FeeCharge`, not executed on a stale balance.
/// `broken_nonce` also makes S2's *later* txs unreachable this
/// block (a failed charge consumes no nonce, so they would run
/// with a gap) — the second S2 tx must skip `StaleNonce`.
#[test]
fn same_run_fee_observes_earlier_tx_effects() {
    let mut executor = test_executor(100);
    let drain = Arc::new(DrainModule {
        ledger: Arc::new(LedgerFeeModule {
            balances: Mutex::new(HashMap::new()),
            charged_total: Mutex::new(0),
        }),
        calls: Mutex::new(0),
    });
    let ledger = drain.ledger.clone();
    primitives::sync::lock_state(&ledger.balances).extend([
        (Address([7u8; 20]), 1_000), // drainer — can pay
        (Address([8u8; 20]), 60),    // victim — can pay 50, until drained
    ]);
    executor.register_module(drain.clone());
    executor.register_module(ledger.clone());
    executor.set_fee_module(9);

    // Run order matters, so build the block directly rather than
    // round-tripping the mempool: tx1 drains S2's balance; tx2
    // (S2, fee 50) then cannot pay under sequential semantics;
    // tx3 (S2, nonce 1) is unreachable behind the broken chain.
    let drain_tx = make_tx_with_fee_and_sender(1, &Address([8u8; 20]).0, 0, 10, 7);
    let victim_tx = make_tx_with_fee_and_sender(1, &[0xAA], 0, 50, 8);
    let victim_tx_hash = Hasher::hash_one(Domain::Transaction, &victim_tx.0);
    let follower_tx = make_tx_with_fee_and_sender(1, &[0xBB], 1, 50, 8);
    let follower_tx_hash = Hasher::hash_one(Domain::Transaction, &follower_tx.0);
    executor.finalize_block(&FinalizedBlock {
        context: types::BlockContext::default(),
        height: Height::new(0),
        txs: vec![drain_tx, victim_tx, follower_tx],
        signers: Vec::new(),
    });

    assert_eq!(
        executor.tx_outcome(&victim_tx_hash),
        Some(TxOutcome::Skipped { reason: TxSkipReason::FeeCharge }),
        "the drained sender's fee must be charged post-effects — and fail"
    );
    assert_eq!(
        executor.tx_outcome(&follower_tx_hash),
        Some(TxOutcome::Skipped { reason: TxSkipReason::StaleNonce }),
        "the failed charge consumes no nonce — the follower is unreachable"
    );
    assert_eq!(*primitives::sync::lock_state(&drain.calls), 1, "only the drain tx executed");
    assert_eq!(
        *primitives::sync::lock_state(&ledger.charged_total),
        10,
        "only the drain tx's fee was collected"
    );
}

// ---- M2 fix: process_proposal validation tests ----

#[test]
fn process_proposal_accepts_valid_tx() {
    let mut executor = test_executor(100);
    executor.register_module(Arc::new(CounterModule::new()));
    let tx = make_tx(1, &[42]);
    let proposal = Proposal { height: Height::new(0), txs: vec![tx], attestation: None };
    assert!(matches!(executor.process_proposal(&proposal), Verdict::Accept));
}

#[test]
fn process_proposal_rejects_too_short_tx() {
    let mut executor = test_executor(100);
    executor.register_module(Arc::new(CounterModule::new()));
    let proposal = Proposal {
        height: Height::new(0),
        txs: vec![TxBytes::new(vec![1, 2, 3])], // way too short
        attestation: None,
    };
    match executor.process_proposal(&proposal) {
        Verdict::Reject { reason } => assert!(reason.contains("malformed")),
        Verdict::Accept => panic!("should reject too-short tx"),
    }
}

#[test]
fn process_proposal_rejects_unknown_module() {
    let mut executor = test_executor(100);
    executor.register_module(Arc::new(CounterModule::new()));
    let tx = make_tx(99, &[1]); // module 99 is not registered
    let proposal = Proposal { height: Height::new(0), txs: vec![tx], attestation: None };
    match executor.process_proposal(&proposal) {
        Verdict::Reject { reason } => assert!(reason.contains("unknown module")),
        Verdict::Accept => panic!("should reject unknown module"),
    }
}

#[test]
fn process_proposal_rejects_malformed_context() {
    let mut executor = test_executor(100);
    executor.register_module(Arc::new(CounterModule::new()));
    // A tx with 37 bytes (minimum for module ID) but with a
    // malformed sender (not a valid address — but actually
    // any 20 bytes is a valid Address, so we need to test a
    // different malformation). Let's use a tx that's exactly
    // 36 bytes (no module ID byte) — this should be rejected
    // as "too short for module ID".
    let mut bytes = vec![0u8; 36]; // 20 + 8 + 8, no module ID
    bytes.push(1); // add module ID
    // Actually this is valid. Let's make a tx with a bad nonce
    // section — but u64::from_le_bytes never fails on 8 bytes.
    // The real malformation is a tx shorter than 36 bytes.
    let short_tx = TxBytes::new(vec![0u8; 30]); // < 36 bytes
    let proposal = Proposal { height: Height::new(0), txs: vec![short_tx], attestation: None };
    match executor.process_proposal(&proposal) {
        Verdict::Reject { reason } => assert!(reason.contains("malformed")),
        Verdict::Accept => panic!("should reject malformed tx"),
    }
}

// ---- Preverification cache key fix ----

/// A test module that records whether `handle_batch_preverified`
/// (the cache-hit path) or `handle_batch` (the fallback path) was
/// called. This lets us prove the preverify cache actually hits.
struct PreverifyTrackingModule {
    preverified_calls: Mutex<usize>,
    fallback_calls: Mutex<usize>,
}

impl PreverifyTrackingModule {
    fn new() -> Self {
        Self { preverified_calls: Mutex::new(0), fallback_calls: Mutex::new(0) }
    }
}

impl Module for PreverifyTrackingModule {
    fn name(&self) -> &'static str {
        "preverify-tracker"
    }
    fn id(&self) -> u8 {
        2
    }
    fn begin_block(&self, _height: Height) {}
    fn handle(&self, _ctx: &TxContext, _msg: &[u8]) -> Result<Vec<Event>, ExecError> {
        Ok(vec![])
    }
    fn end_block(&self, _height: Height) -> Vec<Event> {
        Vec::new()
    }
    fn state_root(&self) -> Hash {
        Hash::ZERO
    }
    // Self-funded so the run takes `dispatch_run` — fee-paying
    // runs interleave charge→handle per tx and never reach the
    // batch/preverified paths this test is observing.
    fn pays_own_fee(&self) -> bool {
        true
    }
    fn preverify_batch<'a>(
        &self,
        msgs: &'a [&'a [u8]],
    ) -> Vec<Result<PreverifiedTx<'a>, ExecError>> {
        // Return a non-zero sender — a zero sender is the
        // "no pre-verification" placeholder and is no longer
        // cached by `ingest_tx`.
        msgs.iter().map(|raw| Ok(PreverifiedTx { raw, sender: [0x42; 20] })).collect()
    }
    fn handle_batch_preverified(
        &self,
        _ctxs: &[TxContext],
        txs: &[PreverifiedTx<'_>],
    ) -> Vec<Result<Vec<Event>, ExecError>> {
        *primitives::sync::lock_state(&self.preverified_calls) += txs.len();
        (0..txs.len()).map(|_| Ok(vec![])).collect()
    }
    fn handle_batch(&self, batch: &[(TxContext, &[u8])]) -> Vec<Result<Vec<Event>, ExecError>> {
        *primitives::sync::lock_state(&self.fallback_calls) += batch.len();
        (0..batch.len()).map(|_| Ok(vec![])).collect()
    }
}

/// Prove the preverify cache key matches between `ingest_tx` and
/// `execute_block`. Before the fix, `ingest_tx` cached under the
/// full-tx hash but `execute_block` looked up under the payload
/// hash — a guaranteed miss. After the fix, both use the full-tx
/// hash, so the preverified path is taken.
#[test]
fn preverify_cache_key_matches_between_ingest_and_execute() {
    let mut executor = test_executor(100);
    let tracker = Arc::new(PreverifyTrackingModule::new());
    executor.register_module(tracker.clone());

    // Ingest a tx — this caches the preverified sender under the
    // full-tx hash.
    let tx = make_tx(2, &[0xAA]);
    executor.ingest_tx(tx.clone());

    // Prepare + finalize a block containing that tx.
    let budget = types::BlockBudget { max_bytes: 1 << 20, max_gas: 1 << 30 };
    let proposal = executor.prepare_proposal(&budget);
    assert_eq!(proposal.txs.len(), 1, "the ingested tx should be in the proposal");
    let block = FinalizedBlock {
        context: types::BlockContext::default(),
        height: Height::new(0),
        txs: proposal.txs,
        signers: Vec::new(),
    };
    executor.finalize_block(&block);

    // The preverified path should have been taken (cache hit),
    // not the fallback path (cache miss).
    let preverified = *primitives::sync::lock_state(&tracker.preverified_calls);
    let fallback = *primitives::sync::lock_state(&tracker.fallback_calls);
    assert_eq!(preverified, 1, "preverified path should have been used (cache hit)");
    assert_eq!(fallback, 0, "fallback path should not have been used (no cache miss)");
}

/// A test module with a *real* `preverify_batch` (returns a
/// non-zero recovered sender, like the EVM's signature recovery)
/// that deliberately does NOT override `handle_batch_preverified`.
/// The default impl is what executes — this is the shape every
/// native module has once it gains payload-level pre-verification.
/// `handle` records the `TxContext` each tx ran under so the test
/// can prove per-tx identity propagation.
struct CtxRecordingModule {
    seen: Mutex<Vec<TxContext>>,
}

impl CtxRecordingModule {
    fn new() -> Self {
        Self { seen: Mutex::new(Vec::new()) }
    }
}

impl Module for CtxRecordingModule {
    fn name(&self) -> &'static str {
        "ctx-recorder"
    }
    fn id(&self) -> u8 {
        7
    }
    fn begin_block(&self, _height: Height) {}
    fn handle(&self, ctx: &TxContext, _msg: &[u8]) -> Result<Vec<Event>, ExecError> {
        primitives::sync::lock_state(&self.seen).push(*ctx);
        Ok(vec![])
    }
    fn end_block(&self, _height: Height) -> Vec<Event> {
        Vec::new()
    }
    fn state_root(&self) -> Hash {
        Hash::ZERO
    }
    fn preverify_batch<'a>(
        &self,
        msgs: &'a [&'a [u8]],
    ) -> Vec<Result<PreverifiedTx<'a>, ExecError>> {
        // A non-zero sender marks "the module verified this
        // payload" — the executor caches it so `execute_block`
        // takes the preverified path.
        msgs.iter().map(|raw| Ok(PreverifiedTx { raw, sender: [0x42; 20] })).collect()
    }
}

/// Records every `(height, BlockContext)` the executor delivers —
/// the oracle proving the consensus execution context crosses the
/// application boundary verbatim.
struct BlockCtxRecorder {
    seen: Mutex<Vec<(Height, types::BlockContext)>>,
}

impl BlockCtxRecorder {
    fn new() -> Self {
        Self { seen: Mutex::new(Vec::new()) }
    }
}

impl Module for BlockCtxRecorder {
    fn name(&self) -> &'static str {
        "block-ctx-recorder"
    }
    fn id(&self) -> u8 {
        6
    }
    fn begin_block(&self, _height: Height) {}
    fn begin_block_ctx(&self, height: Height, ctx: &types::BlockContext) {
        primitives::sync::lock_state(&self.seen).push((height, *ctx));
    }
    fn handle(&self, _ctx: &TxContext, _msg: &[u8]) -> Result<Vec<Event>, ExecError> {
        Ok(vec![])
    }
    fn end_block(&self, _height: Height) -> Vec<Event> {
        Vec::new()
    }
    fn state_root(&self) -> Hash {
        Hash::ZERO
    }
}

/// The execution context committed on the `FinalizedBlock` must
/// reach modules verbatim — timestamp, beneficiary, and gas
/// limit all arrive exactly as consensus produced them.
#[test]
fn execute_block_delivers_consensus_context() {
    let mut executor = test_executor(100);
    let recorder = Arc::new(BlockCtxRecorder::new());
    executor.register_module(recorder.clone());

    let ctx = types::BlockContext {
        timestamp_ms: 1_700_000_000_123,
        beneficiary: Address([0x77; 20]),
        gas_limit: 42_000,
    };
    let block =
        FinalizedBlock { height: Height::new(3), txs: vec![], signers: vec![], context: ctx };
    executor.finalize_block(&block);

    let seen = primitives::sync::lock_state(&recorder.seen);
    assert_eq!(seen.as_slice(), &[(Height::new(3), ctx)]);
}

/// Regression test for the cached-execution identity bug: the
/// preverified path must execute each tx under **its own**
/// `TxContext` — sender, nonce, and fee — not the first tx's.
/// Before the fix, `execute_block` passed `group[0].0` and the
/// default `handle_batch_preverified` replicated it across every
/// tx, so all txs in a cached group ran as the first sender.
/// Because every validator with the same cache population made
/// the same mistake the state roots still agreed — the bug was
/// silent — but a validator whose cache missed (never ingested
/// the tx, e.g. received it only via proposal) executed
/// correctly and *diverged*.
#[test]
fn preverified_path_preserves_per_tx_context() {
    let mut executor = test_executor(100);
    let recorder = Arc::new(CtxRecordingModule::new());
    executor.register_module(recorder.clone());

    // Two txs from different senders — both nonce 0 is legal
    // because nonces are per-sender.
    let tx_a = make_tx_with_fee_and_sender(7, &[1], 0, 100, 0xA1);
    let tx_b = make_tx_with_fee_and_sender(7, &[2], 0, 100, 0xB2);
    executor.ingest_tx(tx_a);
    executor.ingest_tx(tx_b);

    let budget = types::BlockBudget { max_bytes: 1 << 20, max_gas: 1 << 30 };
    let proposal = executor.prepare_proposal(&budget);
    assert_eq!(proposal.txs.len(), 2, "both txs should be in the proposal");
    let block = FinalizedBlock {
        context: types::BlockContext::default(),
        height: Height::new(0),
        txs: proposal.txs,
        signers: Vec::new(),
    };
    executor.finalize_block(&block);

    let seen = primitives::sync::lock_state(&recorder.seen);
    assert_eq!(seen.len(), 2, "both txs should have executed");
    // The mempool may reorder txs, so don't assume group order —
    // the property is that *each* tx ran under its own context:
    // both senders must appear exactly once.
    let mut senders: Vec<primitives::Address> = seen.iter().map(|c| c.sender).collect();
    senders.sort();
    assert_eq!(
        senders,
        vec![Address([0xA1; 20]), Address([0xB2; 20])],
        "each tx must execute under its own sender, not the group leader's"
    );
}

// ---- H4 fix: mempool replay protection ----

/// H4: After a tx with nonce N is executed, re-submitting the
/// same tx (or any tx with nonce < N+1) must be rejected by
/// `ingest_tx`. Without this, a tx removed from the mempool
/// after block selection can be re-submitted and re-executed.
#[test]
fn h4_ingest_rejects_stale_nonce_after_execution() {
    let mut executor = test_executor(100);
    let counter = Arc::new(CounterModule::new());
    executor.register_module(counter.clone());

    // Submit and execute nonce 0.
    let tx0 = make_tx_with_nonce(1, &[0], 0);
    executor.ingest_tx(tx0);
    let budget = types::BlockBudget { max_bytes: 1 << 20, max_gas: 1 << 30 };
    let proposal = executor.prepare_proposal(&budget);
    let block = FinalizedBlock {
        context: types::BlockContext::default(),
        height: Height::new(0),
        txs: proposal.txs,
        signers: Vec::new(),
    };
    executor.finalize_block(&block);

    // Re-submit nonce 0 — must be rejected (replay).
    let tx0_again = make_tx_with_nonce(1, &[0], 0);
    match executor.ingest_tx(tx0_again) {
        MempoolAck::Rejected { reason } => {
            assert!(reason.contains("replay"), "expected replay rejection, got: {reason}");
        }
        MempoolAck::Accepted => panic!("stale nonce must be rejected (replay)"),
    }

    // Nonce 1 should still be accepted.
    let tx1 = make_tx_with_nonce(1, &[1], 1);
    assert!(matches!(executor.ingest_tx(tx1), MempoolAck::Accepted));
}

/// Regression test: `ingest_tx_batch` must reject txs with stale
/// nonces (replay protection). Before the fix, the batch path
/// skipped the executed-nonce check that `ingest_tx` enforced,
/// allowing replayed txs to enter the mempool via the batch path.
#[test]
fn h4_ingest_batch_rejects_stale_nonce_after_execution() {
    let mut executor = test_executor(100);
    let counter = Arc::new(CounterModule::new());
    executor.register_module(counter.clone());

    // Submit and execute nonce 0.
    let tx0 = make_tx_with_nonce(1, &[0], 0);
    executor.ingest_tx(tx0);
    let budget = types::BlockBudget { max_bytes: 1 << 20, max_gas: 1 << 30 };
    let proposal = executor.prepare_proposal(&budget);
    let block = FinalizedBlock {
        context: types::BlockContext::default(),
        height: Height::new(0),
        txs: proposal.txs,
        signers: Vec::new(),
    };
    executor.finalize_block(&block);

    // Re-submit nonce 0 via the batch path — must be rejected.
    let tx0_again = make_tx_with_nonce(1, &[0], 0);
    let tx1 = make_tx_with_nonce(1, &[1], 1);
    let results = executor.ingest_tx_batch(vec![tx0_again, tx1]);
    assert_eq!(results.len(), 2);
    match &results[0] {
        MempoolAck::Rejected { reason } => {
            assert!(
                reason.contains("replay"),
                "expected replay rejection for stale nonce in batch, got: {reason}"
            );
        }
        MempoolAck::Accepted => panic!("stale nonce must be rejected in batch path (replay)"),
    }
    // Nonce 1 should still be accepted.
    assert!(
        matches!(results[1], MempoolAck::Accepted),
        "valid nonce must be accepted in batch path"
    );
}

// ---- H5 fix: process_proposal nonce ordering ----

/// H5: `process_proposal` must reject a proposal where a
/// sender's nonces are not strictly contiguous. A byzantine
/// proposer cannot reorder same-account txs.
#[test]
fn h5_process_proposal_rejects_nonce_gap() {
    let mut executor = test_executor(100);
    executor.register_module(Arc::new(CounterModule::new()));

    // Two txs from the same sender: nonce 0 then nonce 2 (gap).
    let tx0 = make_tx_with_nonce(1, &[0], 0);
    let tx2 = make_tx_with_nonce(1, &[2], 2);
    let proposal = Proposal { height: Height::new(0), txs: vec![tx0, tx2], attestation: None };
    match executor.process_proposal(&proposal) {
        Verdict::Reject { reason } => {
            assert!(reason.contains("nonce gap"), "expected nonce gap rejection, got: {reason}");
        }
        Verdict::Accept => panic!("nonce gap must be rejected"),
    }
}

/// H5: `process_proposal` must reject a proposal where a
/// sender's nonces are out of order (e.g. nonce 1 before nonce 0).
#[test]
fn h5_process_proposal_rejects_nonce_reorder() {
    let mut executor = test_executor(100);
    executor.register_module(Arc::new(CounterModule::new()));

    // Nonce 1 before nonce 0 — reorder.
    let tx1 = make_tx_with_nonce(1, &[1], 1);
    let tx0 = make_tx_with_nonce(1, &[0], 0);
    let proposal = Proposal { height: Height::new(0), txs: vec![tx1, tx0], attestation: None };
    match executor.process_proposal(&proposal) {
        Verdict::Reject { reason } => {
            assert!(reason.contains("nonce gap"), "expected nonce gap rejection, got: {reason}");
        }
        Verdict::Accept => panic!("nonce reorder must be rejected"),
    }
}

/// H5: `process_proposal` must accept a proposal with
/// contiguous, strictly increasing nonces.
#[test]
fn h5_process_proposal_accepts_contiguous_nonces() {
    let mut executor = test_executor(100);
    executor.register_module(Arc::new(CounterModule::new()));

    let tx0 = make_tx_with_nonce(1, &[0], 0);
    let tx1 = make_tx_with_nonce(1, &[1], 1);
    let tx2 = make_tx_with_nonce(1, &[2], 2);
    let proposal = Proposal { height: Height::new(0), txs: vec![tx0, tx1, tx2], attestation: None };
    assert!(matches!(executor.process_proposal(&proposal), Verdict::Accept));
}

/// H5: `execute_block` must skip txs with stale nonces (nonce
/// already executed). This is the cross-block continuity check.
#[test]
fn h5_execute_block_skips_stale_nonce() {
    let mut executor = test_executor(100);
    let counter = Arc::new(CounterModule::new());
    executor.register_module(counter.clone());

    // Execute nonce 0 in block 0.
    let tx0 = make_tx_with_nonce(1, &[0], 0);
    executor.ingest_tx(tx0);
    let budget = types::BlockBudget { max_bytes: 1 << 20, max_gas: 1 << 30 };
    let proposal = executor.prepare_proposal(&budget);
    let block0 = FinalizedBlock {
        context: types::BlockContext::default(),
        height: Height::new(0),
        txs: proposal.txs,
        signers: Vec::new(),
    };
    executor.finalize_block(&block0);
    assert_eq!(*primitives::sync::lock_state(&counter.count), 1);

    // Try to execute nonce 0 again in block 1 — must be skipped.
    let tx0_again = make_tx_with_nonce(1, &[0], 0);
    let block1 = FinalizedBlock {
        context: types::BlockContext::default(),
        height: Height::new(1),
        txs: vec![tx0_again],
        signers: Vec::new(),
    };
    executor.finalize_block(&block1);

    // Counter should still be 1 — the stale tx was skipped.
    assert_eq!(
        *primitives::sync::lock_state(&counter.count),
        1,
        "stale nonce tx must be skipped during execution"
    );
}

/// Regression: nonce `u64::MAX` is reserved. Executing it would
/// wrap the sender's next-expected counter (`MAX + 1` → 0) and
/// reopen the whole nonce range to replay. The tx must be
/// rejected at admission, skipped at execution, and rejected at
/// proposal validation.
#[test]
fn nonce_u64_max_is_reserved() {
    let mut executor = test_executor(100);
    let counter = Arc::new(CounterModule::new());
    executor.register_module(counter.clone());

    // Admission: nonce MAX is rejected outright.
    let tx_max = make_tx_with_nonce(1, &[9], u64::MAX);
    assert!(
        matches!(executor.ingest_tx(tx_max.clone()), MempoolAck::Rejected { .. }),
        "nonce u64::MAX must be rejected at admission"
    );

    // Execution: a MAX-nonce tx smuggled into a block is skipped
    // — the counter does not move and the nonce map is not
    // poisoned.
    let block = FinalizedBlock {
        context: types::BlockContext::default(),
        height: Height::new(0),
        txs: vec![tx_max],
        signers: Vec::new(),
    };
    executor.finalize_block(&block);
    assert_eq!(*primitives::sync::lock_state(&counter.count), 0, "reserved nonce must not execute");

    // The nonce map must still expect 0 — a subsequent nonce-0 tx
    // executes normally (no wrap-induced replay window).
    let tx0 = make_tx_with_nonce(1, &[0], 0);
    let block1 = FinalizedBlock {
        context: types::BlockContext::default(),
        height: Height::new(1),
        txs: vec![tx0],
        signers: Vec::new(),
    };
    executor.finalize_block(&block1);
    assert_eq!(
        *primitives::sync::lock_state(&counter.count),
        1,
        "nonce 0 must still execute after a smuggled MAX nonce"
    );
}

/// H5+: `ingest_tx` (mempool admission) must reject txs with
/// stale nonces (nonce < `executed_nonce`). This is the cross-block
/// nonce anchoring gate — it prevents replay attacks where a tx
/// removed from the mempool after block selection is re-submitted.
/// `process_proposal` does NOT check cross-block anchoring because
/// the pipelined consensus may propose before the previous block's
/// execution completes.
#[test]
fn h5_ingest_tx_rejects_stale_nonce_after_execution() {
    let mut executor = test_executor(100);
    let counter = Arc::new(CounterModule::new());
    executor.register_module(counter.clone());

    // Execute nonce 0 in block 0.
    let tx0 = make_tx_with_nonce(1, &[0], 0);
    executor.ingest_tx(tx0);
    let budget = types::BlockBudget { max_bytes: 1 << 20, max_gas: 1 << 30 };
    let proposal = executor.prepare_proposal(&budget);
    let block0 = FinalizedBlock {
        context: types::BlockContext::default(),
        height: Height::new(0),
        txs: proposal.txs,
        signers: Vec::new(),
    };
    executor.finalize_block(&block0);
    assert_eq!(*primitives::sync::lock_state(&counter.count), 1);

    // Try to ingest nonce 0 again (stale) — must be rejected.
    let tx0_stale = make_tx_with_nonce(1, &[0], 0);
    let ack = executor.ingest_tx(tx0_stale);
    assert!(matches!(ack, MempoolAck::Rejected { .. }), "stale nonce must be rejected by mempool");

    // Ingest nonce 1 (correct) — must be accepted.
    let tx1 = make_tx_with_nonce(1, &[1], 1);
    let ack = executor.ingest_tx(tx1);
    assert!(matches!(ack, MempoolAck::Accepted), "correct nonce must be accepted by mempool");
}

/// H4/H5: snapshot export/import must preserve the executed-nonce
/// map so replay protection survives restarts.
/// An EVM transaction must not be able to advance *another*
/// account's executor nonce.
///
/// The EVM recovers its sender and nonce from the signed RLP, so a
/// caller can wrap their own valid payload in any envelope. Before
/// this fix the executor drove `executed_nonce` from the envelope's
/// declared `(sender, nonce)`, so such an envelope advanced the
/// victim's counter without the victim's authorization —
/// desynchronizing ordinary Ethereum submissions from the real EVM
/// account nonce. The envelope must not touch account-indexed nonce
/// state for a module that authenticates itself.
#[test]
fn self_authenticating_module_cannot_advance_another_accounts_nonce() {
    const VICTIM: u8 = 0x11;
    let mut executor = test_executor(100);
    executor.register_module(Arc::new(SelfAuthModule));

    // The attacker's payload, wrapped in the victim's envelope at
    // the victim's nonce. Module 3 is `SelfAuthModule` (see the
    // signed-transaction section below), which reports
    // `authenticates_sender() == true` exactly like the EVM.
    let tx = make_tx_with_fee_and_sender(3, &[0xAA], 0, 0, VICTIM);
    executor.finalize_block(&FinalizedBlock {
        context: types::BlockContext::default(),
        height: Height::new(0),
        txs: vec![tx],
        signers: vec![],
    });

    let snap = executor.export_snapshot();
    assert!(
        !snap.executed_nonces.iter().any(|(a, _)| *a == Address([VICTIM; 20])),
        "a self-authenticating module must not advance the envelope sender's nonce"
    );
}

/// Control: a module that authenticates from the envelope *does* own
/// the nonce gate, so its counter still advances normally.
#[test]
fn envelope_authenticating_module_still_advances_nonce() {
    const SENDER: u8 = 0x22;
    let mut executor = test_executor(100);
    executor.register_module(Arc::new(CounterModule::new()));

    let tx = make_tx_with_fee_and_sender(1, &[0xAA], 0, 0, SENDER);
    executor.finalize_block(&FinalizedBlock {
        context: types::BlockContext::default(),
        height: Height::new(0),
        txs: vec![tx],
        signers: vec![],
    });

    let snap = executor.export_snapshot();
    assert_eq!(
        snap.executed_nonces.iter().find(|(a, _)| *a == Address([SENDER; 20])).map(|(_, n)| *n),
        Some(1),
        "an envelope-authenticating module must advance its sender's nonce"
    );
}

#[test]
fn h4h5_snapshot_preserves_executed_nonce() {
    let mut executor = test_executor(100);
    let counter = Arc::new(CounterModule::new());
    executor.register_module(counter.clone());

    // Execute nonce 0 and nonce 1.
    for n in 0..2u64 {
        let tx = make_tx_with_nonce(1, &[u8::try_from(n).unwrap_or(0xff)], n);
        executor.ingest_tx(tx);
        let budget = types::BlockBudget { max_bytes: 1 << 20, max_gas: 1 << 30 };
        let proposal = executor.prepare_proposal(&budget);
        let block = FinalizedBlock {
            context: types::BlockContext::default(),
            height: Height::new(n),
            txs: proposal.txs,
            signers: Vec::new(),
        };
        executor.finalize_block(&block);
    }

    // Export snapshot.
    let snapshot = executor.export_snapshot();
    assert_eq!(snapshot.executed_nonces.len(), 1, "one sender in the nonce map");
    assert_eq!(snapshot.executed_nonces[0].1, 2, "next expected nonce is 2");

    // Import into a fresh executor.
    let mut executor2 = test_executor(100);
    executor2.register_module(Arc::new(CounterModule::new()));
    executor2.import_snapshot(&snapshot).expect("import must succeed");

    // Re-submitting nonce 0 must be rejected (replay).
    let tx0 = make_tx_with_nonce(1, &[0], 0);
    match executor2.ingest_tx(tx0) {
        MempoolAck::Rejected { reason } => {
            assert!(
                reason.contains("replay"),
                "expected replay rejection after snapshot import, got: {reason}"
            );
        }
        MempoolAck::Accepted => panic!("stale nonce must be rejected after snapshot import"),
    }

    // Nonce 2 should be accepted (next expected).
    let tx2 = make_tx_with_nonce(1, &[2], 2);
    assert!(matches!(executor2.ingest_tx(tx2), MempoolAck::Accepted));
}

/// The nonce commitment is a set commitment: the XOR-fold must
/// be order-independent, `ExecutedNonces::bump` must keep
/// `root == fold(map)` after every mutation, and removing-then-
/// re-adding a leaf (the rewind path) must cancel cleanly.
/// Before this construction the root was a sorted-concatenation
/// hash recomputed over the whole map every block — O(accounts)
/// per block regardless of how many senders actually executed.
#[test]
fn nonce_root_fold_is_order_free_and_incremental() {
    let a = primitives::Address([0xAA; 20]);
    let b = primitives::Address([0xBB; 20]);
    let c = primitives::Address([0xCC; 20]);

    // Empty map commits to ZERO (no leaves folded).
    assert_eq!(compute_nonce_root(&[]), Hash::ZERO);

    // Order does not matter — same set, same root.
    let forward = compute_nonce_root(&[(a, 1), (b, 2), (c, 3)]);
    let reverse = compute_nonce_root(&[(c, 3), (a, 1), (b, 2)]);
    assert_eq!(forward, reverse, "fold must be order-independent");
    // A different set commits differently.
    assert_ne!(forward, compute_nonce_root(&[(a, 1), (b, 2)]), "extra leaf moves the root");

    // `bump` maintains the invariant incrementally: insert,
    // advance, rewind (fee-failure path), then check against a
    // from-scratch fold after every step.
    let mut local = ExecutedNonces::default();
    let check = |local: &ExecutedNonces| {
        let v: Vec<_> = local.map.iter().map(|(k, v)| (*k, *v)).collect();
        assert_eq!(local.root, compute_nonce_root(&v), "root must track the map");
    };
    check(&local);
    local.bump(a, 1); // new sender
    check(&local);
    local.bump(a, 2); // advance
    check(&local);
    local.bump(a, 1); // rewind — old leaf folds out, new folds in
    check(&local);
    local.bump(b, 7);
    local.bump(c, 4);
    check(&local);
    // Idempotent bump is a net no-op (fold out == fold in).
    local.bump(a, 1);
    check(&local);

    // The per-block overlay: reads see delta-then-base, bumps
    // fold the *effective* leaf out (delta wins over committed),
    // and `finish` returns a delta whose application yields a
    // map whose fold equals the carried root.
    let base = local.clone();
    let mut overlay = BlockNonces::new(&base);
    assert_eq!(overlay.next_expected(&a), Some(1), "base value visible");
    overlay.bump(a, 5); // advance over committed 1
    assert_eq!(overlay.next_expected(&a), Some(5), "delta wins over base");
    overlay.bump(a, 4); // rewind — folds out 5, in 4
    overlay.bump(c, 9); // new sender over committed 4
    let (delta, root) = overlay.finish();
    let mut post = base.clone();
    post.map.extend(delta);
    post.root = root;
    check(&post);
    assert_eq!(post.map.get(&a), Some(&4));
    assert_eq!(post.map.get(&c), Some(&9));
    assert_ne!(post.root, base.root, "touched senders move the root");
}

/// The fold is over set semantics: a crafted snapshot that lists
/// one sender twice would XOR the pair out of the recomputed
/// root while `HashMap::collect` dedupes it — installing a root
/// that no longer matches the installed map (and silently
/// changing the sender's next-expected nonce). Import must
/// reject duplicates outright.
#[test]
fn snapshot_import_rejects_duplicate_nonce_entry() {
    let mut executor = test_executor(100);
    executor.register_module(Arc::new(CounterModule::new()));
    let tx = make_tx_with_nonce(1, &[0], 0);
    executor.ingest_tx(tx);
    let budget = types::BlockBudget { max_bytes: 1 << 20, max_gas: 1 << 30 };
    let proposal = executor.prepare_proposal(&budget);
    executor.finalize_block(&FinalizedBlock {
        context: types::BlockContext::default(),
        height: Height::new(0),
        txs: proposal.txs,
        signers: Vec::new(),
    });
    let mut snapshot = executor.export_snapshot();
    assert_eq!(snapshot.executed_nonces.len(), 1);
    // Duplicate the one entry — the pair XORs out of the fold,
    // so `nonce_root` still verifies against a naive importer.
    let dup = snapshot.executed_nonces[0];
    snapshot.executed_nonces.push(dup);
    let mut executor2 = test_executor(100);
    executor2.register_module(Arc::new(CounterModule::new()));
    assert!(
        matches!(
            executor2.import_snapshot(&snapshot),
            Err(SnapshotImportError::DuplicateNonceEntry)
        ),
        "duplicated nonce entry must be rejected"
    );
}

/// After real blocks execute, the incrementally-maintained root
/// must equal a from-scratch fold of the stored map — the whole
/// point of carrying it is that `execute_block` never recomputes
/// it by scanning.
#[test]
fn executed_nonce_root_tracks_map_across_blocks() {
    let mut executor = test_executor(100);
    executor.register_module(Arc::new(CounterModule::new()));
    for n in 0..3u64 {
        // Two senders in the same block: one insert, one advance.
        for sender in 1..=2u8 {
            let tx = make_tx_with_nonce(sender, &[u8::try_from(n).unwrap_or(0xff)], n);
            executor.ingest_tx(tx);
        }
        let budget = types::BlockBudget { max_bytes: 1 << 20, max_gas: 1 << 30 };
        let proposal = executor.prepare_proposal(&budget);
        executor.finalize_block(&FinalizedBlock {
            context: types::BlockContext::default(),
            height: Height::new(n),
            txs: proposal.txs,
            signers: Vec::new(),
        });
        let en = primitives::sync::lock_state(&executor.executed_nonce);
        let v: Vec<_> = en.map.iter().map(|(a, n)| (*a, *n)).collect();
        assert_eq!(
            en.root,
            compute_nonce_root(&v),
            "maintained root diverged from the map after block {n}"
        );
    }
}

/// Regression test: `process_proposal` must reject a block whose
/// total gas exceeds the block gas limit. Before the fix, the
/// `BlockBudget.max_gas` field was ignored — a byzantine proposer
/// could include unbounded computation in a single block.
#[test]
fn process_proposal_rejects_block_exceeding_gas_limit() {
    let mut executor =
        test_executor_with_config(100, DEFAULT_PARALLEL_THRESHOLD).with_gas_limit(2000);
    executor.register_module(Arc::new(CounterModule::new()));

    // Each tx costs 1000 gas (base) + payload bytes. With a 2000
    // gas limit, we can fit at most 1 tx with a small payload
    // (1000 + N bytes). Two txs would exceed 2000.
    let tx1 = make_tx(1, &[0]);
    let tx2 = make_tx_with_nonce(1, &[1], 1);

    // A proposal with 2 txs (each ~1001 gas) totals ~2002 gas,
    // exceeding the 2000 limit.
    let proposal = Proposal { height: Height::new(0), txs: vec![tx1, tx2], attestation: None };
    let verdict = executor.process_proposal(&proposal);
    match verdict {
        Verdict::Reject { reason } => {
            assert!(reason.contains("gas limit"), "expected gas limit rejection, got: {reason}");
        }
        Verdict::Accept => panic!("block exceeding gas limit must be rejected"),
    }
}

/// Regression test: `process_proposal` must accept a block whose
/// total gas is within the block gas limit.
#[test]
fn process_proposal_accepts_block_within_gas_limit() {
    let mut executor =
        test_executor_with_config(100, DEFAULT_PARALLEL_THRESHOLD).with_gas_limit(10_000);
    executor.register_module(Arc::new(CounterModule::new()));

    // One tx with a small payload: 1000 + 1 = 1001 gas, well
    // within the 10,000 limit.
    let tx = make_tx(1, &[0]);
    let proposal = Proposal { height: Height::new(0), txs: vec![tx], attestation: None };
    let verdict = executor.process_proposal(&proposal);
    assert!(matches!(verdict, Verdict::Accept), "block within gas limit must be accepted");
}

/// Regression test: `execute_block` must skip txs that would
/// exceed the cumulative block gas limit. This is the
/// execution-time enforcement (the proposal-time check is in
/// `process_proposal`).
#[test]
fn execute_block_skips_txs_exceeding_gas_limit() {
    let mut executor =
        test_executor_with_config(100, DEFAULT_PARALLEL_THRESHOLD).with_gas_limit(2000);
    executor.register_module(Arc::new(CounterModule::new()));

    // Two txs, each costing ~1001 gas. The first fits (cumulative
    // 1001 ≤ 2000), the second would push to 2002 > 2000.
    let tx1 = make_tx(1, &[0]);
    let tx2 = make_tx_with_nonce(1, &[1], 1);
    let block = FinalizedBlock {
        context: types::BlockContext::default(),
        height: Height::new(0),
        txs: vec![tx1, tx2],
        signers: Vec::new(),
    };
    executor.finalize_block(&block);

    // Only the first tx should have been executed (counter = 1).
    // The second tx was skipped due to the gas limit.
    let counter = executor.modules[1].as_ref().unwrap();
    let count = counter.state_root();
    assert_eq!(
        count.0[0], 1,
        "only the first tx should execute (gas limit), got counter = {}",
        count.0[0]
    );
}

/// Regression test: `prepare_proposal` must not build a block
/// the validators reject. Before the fix, proposal selection
/// used only the byte budget — a proposer could pack enough
/// gas into `max_bytes` to exceed the block gas limit, and
/// `process_proposal` would reject the whole proposal.
#[test]
fn prepare_proposal_respects_block_gas_limit() {
    let mut executor =
        test_executor_with_config(100, DEFAULT_PARALLEL_THRESHOLD).with_gas_limit(2500);
    executor.register_module(Arc::new(CounterModule::new()));

    // Submit 4 txs, each ~1001 gas (1000 base + 1 byte). Under
    // a 2500 gas cap at most 2 fit (2×1001 = 2002; 3×1001 = 3003).
    for n in 0..4u64 {
        let tx = make_tx_with_nonce(1, &[u8::try_from(n).unwrap_or(0xff)], n);
        assert!(matches!(executor.ingest_tx(tx), MempoolAck::Accepted));
    }

    let budget = types::BlockBudget { max_bytes: 1 << 20, max_gas: 1 << 30 };
    let proposal = executor.prepare_proposal(&budget);
    assert_eq!(proposal.txs.len(), 2, "only two ~1001-gas txs fit under 2500");
    // The built proposal must pass validation.
    assert!(
        matches!(executor.process_proposal(&proposal), Verdict::Accept),
        "a gas-bounded proposal must be accepted"
    );
}

// ---- EIP-712 signed native transactions (item 16) ----

/// A module that self-authenticates (like the EVM): its payload
/// carries its own signature, so an envelope signature on it is
/// malformed by definition.
struct SelfAuthModule;

impl Module for SelfAuthModule {
    fn name(&self) -> &'static str {
        "selfauth"
    }
    fn id(&self) -> u8 {
        3
    }
    fn authenticates_sender(&self) -> bool {
        true
    }
    fn begin_block(&self, _height: Height) {}
    fn handle(&self, _ctx: &TxContext, _msg: &[u8]) -> Result<Vec<Event>, ExecError> {
        Ok(vec![])
    }
    fn end_block(&self, _height: Height) -> Vec<Event> {
        Vec::new()
    }
    fn state_root(&self) -> Hash {
        Hash::ZERO
    }
}

/// Build a signed tx to the counter module with a fresh keypair.
/// Returns `(tx_bytes, sender)`.
fn signed_counter_tx(chain_id: u64, nonce: u64, payload: &[u8]) -> (TxBytes, Address) {
    let (privkey, sender) = crypto::secp::generate_keypair_for_test();
    let tx = mempool::build_signed_tx(&privkey, chain_id, nonce, 0, 1, payload)
        .expect("valid key must sign");
    (tx, sender)
}

/// The signed-envelope codec: `module_id` masks the flag bit and
/// the payload excludes the 65-byte signature.
#[test]
fn signed_envelope_parses_correctly() {
    let (tx, sender) = signed_counter_tx(1, 5, b"my-payload");
    let bytes = tx.as_bytes();
    assert!(is_signed_envelope(bytes));
    assert_eq!(parse_module_id(bytes), Some(1));
    assert_eq!(envelope_signature(bytes).map(<[u8]>::len), Some(65));
    assert_eq!(module_payload(bytes), b"my-payload");
    let ctx = parse_tx_context(bytes).unwrap();
    assert_eq!(ctx.sender, sender);
    assert_eq!(ctx.nonce, 5);
}

/// A properly signed native tx is admitted and executes.
#[test]
fn signed_tx_executes_end_to_end() {
    let mut executor = test_executor(100);
    let counter = Arc::new(CounterModule::new());
    executor.register_module(counter.clone());

    let (tx, _sender) = signed_counter_tx(1, 0, b"inc");
    assert!(matches!(executor.ingest_tx(tx), MempoolAck::Accepted));
    let budget = types::BlockBudget { max_bytes: 1 << 20, max_gas: 1 << 30 };
    let proposal = executor.prepare_proposal(&budget);
    assert_eq!(proposal.txs.len(), 1);
    executor.finalize_block(&FinalizedBlock {
        context: types::BlockContext::default(),
        height: Height::new(0),
        txs: proposal.txs,
        signers: Vec::new(),
    });
    assert_eq!(*primitives::sync::lock_state(&counter.count), 1);
}

/// A corrupted signature is rejected at mempool admission.
#[test]
fn bad_signature_rejected_at_ingest() {
    let mut executor = test_executor(100);
    executor.register_module(Arc::new(CounterModule::new()));

    let (tx, _sender) = signed_counter_tx(1, 0, b"inc");
    let mut bytes = tx.as_bytes().to_vec();
    bytes[ENVELOPE_SIG_OFFSET] ^= 0xFF; // corrupt first byte of r
    let ack = executor.ingest_tx(TxBytes::new(bytes));
    assert!(matches!(ack, MempoolAck::Rejected { .. }), "bad sig must be rejected");
}

/// A signature produced for chain 2 is rejected on chain 1 —
/// the domain separator binds the chain ID.
#[test]
fn cross_chain_signature_rejected() {
    let mut executor = test_executor(100).with_chain_id(1);
    executor.register_module(Arc::new(CounterModule::new()));

    let (tx, _sender) = signed_counter_tx(2, 0, b"inc");
    assert!(matches!(executor.ingest_tx(tx), MempoolAck::Rejected { .. }));
}

/// A signed envelope whose declared sender was overwritten with
/// a victim's address is rejected — the signature proves the
/// signer's key, not the claimed field.
#[test]
fn forged_declared_sender_rejected() {
    let mut executor = test_executor(100);
    executor.register_module(Arc::new(CounterModule::new()));

    let victim = Address([0xEE; 20]);
    let (tx, _sender) = signed_counter_tx(1, 0, b"inc");
    let mut bytes = tx.as_bytes().to_vec();
    bytes[..20].copy_from_slice(&victim.0); // forge sender
    assert!(matches!(executor.ingest_tx(TxBytes::new(bytes)), MempoolAck::Rejected { .. }));
}

/// Under `UnsignedTxPolicy::Reject`, an unsigned native tx is
/// rejected at admission — closing the unauthenticated-sender
/// hole.
#[test]
fn unsigned_tx_rejected_when_required() {
    let mut executor = Executor::new(100).with_unsigned_tx_policy(UnsignedTxPolicy::Reject);
    executor.register_module(Arc::new(CounterModule::new()));

    let ack = executor.ingest_tx(make_tx(1, b"unsigned"));
    assert!(matches!(ack, MempoolAck::Rejected { .. }), "unsigned must be rejected");
}

/// Under `Reject`, an unsigned tx injected into a finalized block
/// (bypassing this node's mempool — e.g. proposed by another
/// validator) is skipped deterministically at execution.
#[test]
fn unsigned_tx_skipped_at_execution_when_required() {
    let mut executor = Executor::new(100).with_unsigned_tx_policy(UnsignedTxPolicy::Reject);
    let counter = Arc::new(CounterModule::new());
    executor.register_module(counter.clone());

    executor.finalize_block(&FinalizedBlock {
        context: types::BlockContext::default(),
        height: Height::new(0),
        txs: vec![make_tx(1, b"unsigned")],
        signers: Vec::new(),
    });
    assert_eq!(
        *primitives::sync::lock_state(&counter.count),
        0,
        "unsigned tx must not execute under Reject"
    );
}

/// A signed tx that never touched this node's mempool (foreign
/// proposal) is verified inline at execution and executes.
#[test]
fn foreign_signed_tx_verified_at_execution() {
    let mut executor = Executor::new(100).with_unsigned_tx_policy(UnsignedTxPolicy::Reject);
    let counter = Arc::new(CounterModule::new());
    executor.register_module(counter.clone());

    let (tx, _sender) = signed_counter_tx(1, 0, b"inc");
    executor.finalize_block(&FinalizedBlock {
        context: types::BlockContext::default(),
        height: Height::new(0),
        txs: vec![tx],
        signers: Vec::new(),
    });
    assert_eq!(*primitives::sync::lock_state(&counter.count), 1, "foreign signed tx must execute");
}

/// A signed tx whose signature was computed over a different
/// payload is skipped at execution — the signature binds the
/// exact module message bytes.
#[test]
fn tampered_payload_rejected_at_execution() {
    let mut executor = test_executor(100);
    let counter = Arc::new(CounterModule::new());
    executor.register_module(counter.clone());

    let (tx, _sender) = signed_counter_tx(1, 0, b"orig");
    let mut bytes = tx.as_bytes().to_vec();
    // Rewrite the payload (last 4 bytes).
    let n = bytes.len();
    bytes[n - 4..].copy_from_slice(b"evil");

    executor.finalize_block(&FinalizedBlock {
        context: types::BlockContext::default(),
        height: Height::new(0),
        txs: vec![TxBytes::new(bytes)],
        signers: Vec::new(),
    });
    assert_eq!(
        *primitives::sync::lock_state(&counter.count),
        0,
        "tampered payload must not execute"
    );
}

/// An envelope signature on a self-authenticating module is
/// malformed — it would corrupt the module's own payload.
#[test]
fn flagged_self_auth_module_rejected() {
    let mut executor = test_executor(100);
    executor.register_module(Arc::new(SelfAuthModule));

    // Flagged envelope routed to module 3 (SelfAuthModule).
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&Address([1; 20]).0);
    bytes.extend_from_slice(&0u64.to_le_bytes());
    bytes.extend_from_slice(&0u64.to_le_bytes());
    bytes.push(3 | 0x80); // SIGNED_FLAG on a self-auth module
    bytes.extend_from_slice(&[0u8; 65]); // dummy sig
    bytes.extend_from_slice(b"payload");

    assert!(matches!(executor.ingest_tx(TxBytes::new(bytes)), MempoolAck::Rejected { .. }));
}

/// The same malformed tx is rejected statically at proposal
/// validation — the flag on a self-auth module is a structural
/// error, no crypto needed.
#[test]
fn proposal_rejects_flagged_self_auth() {
    let mut executor = test_executor(100);
    executor.register_module(Arc::new(SelfAuthModule));

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&Address([1; 20]).0);
    bytes.extend_from_slice(&0u64.to_le_bytes());
    bytes.extend_from_slice(&0u64.to_le_bytes());
    bytes.push(3 | 0x80);
    bytes.extend_from_slice(&[0u8; 65]);
    bytes.extend_from_slice(b"payload");

    let proposal =
        Proposal { height: Height::new(0), txs: vec![TxBytes::new(bytes)], attestation: None };
    let verdict = executor.process_proposal(&proposal);
    assert!(matches!(verdict, Verdict::Reject { .. }), "flagged self-auth must reject");
}

/// A signed tx truncated inside the signature field is a clean
/// rejection, not a panic.
#[test]
fn truncated_signed_envelope_rejected_cleanly() {
    let mut executor = test_executor(100);
    executor.register_module(Arc::new(CounterModule::new()));

    let (tx, _s) = signed_counter_tx(1, 0, b"inc");
    let bytes = tx.as_bytes().to_vec();
    let truncated = bytes[..ENVELOPE_SIG_OFFSET + 30].to_vec();
    assert!(matches!(executor.ingest_tx(TxBytes::new(truncated)), MempoolAck::Rejected { .. }));
}

/// Batch ingestion applies the same signature policy per tx.
#[test]
fn batch_ingest_enforces_signatures() {
    let mut executor = Executor::new(100).with_unsigned_tx_policy(UnsignedTxPolicy::Reject);
    executor.register_module(Arc::new(CounterModule::new()));

    let (signed, _s) = signed_counter_tx(1, 0, b"ok");
    let unsigned = make_tx(1, b"no-sig");
    let results = executor.ingest_tx_batch(vec![signed, unsigned]);
    assert!(matches!(results[0], MempoolAck::Accepted));
    assert!(matches!(results[1], MempoolAck::Rejected { .. }));
}

/// A module with a declared schema version, a migration spy, an
/// optional halt schedule, and trivial KV export/import — the
/// fixture for every upgrade-mechanism test.
struct VersionedModule {
    /// Declared `state_version` — what this "binary" writes.
    version: u32,
    /// Heights at which `scheduled_halt_height` reports a halt.
    halt: Mutex<Option<u64>>,
    /// Records every `migrate(from)` argument — the assertion
    /// surface proving the executor drove the migration.
    migrate_calls: Mutex<Vec<u32>>,
    /// When set, `migrate` fails — exercises the fail-closed
    /// import path.
    migrate_fails: bool,
    /// Trivial in-memory KV so `export_state`/`import_state` have
    /// something to round-trip.
    kv: Mutex<Vec<(Hash, Vec<u8>)>>,
}

impl VersionedModule {
    fn new(version: u32) -> Arc<Self> {
        Arc::new(Self {
            version,
            halt: Mutex::new(None),
            migrate_calls: Mutex::new(Vec::new()),
            migrate_fails: false,
            kv: Mutex::new(Vec::new()),
        })
    }
}

impl Module for VersionedModule {
    fn name(&self) -> &'static str {
        "versioned"
    }
    fn id(&self) -> u8 {
        9
    }
    fn begin_block(&self, _height: Height) {}
    fn handle(&self, _ctx: &TxContext, _msg: &[u8]) -> Result<Vec<Event>, ExecError> {
        Ok(vec![Event { module: "versioned", kind: "noop", data: vec![] }])
    }
    fn end_block(&self, _height: Height) -> Vec<Event> {
        Vec::new()
    }
    fn state_root(&self) -> Hash {
        // A stable non-zero root — upgrade tests assert on
        // version plumbing, not root math.
        Hash([9u8; 32])
    }
    fn state_version(&self) -> u32 {
        self.version
    }
    fn migrate(&self, from: u32) -> Result<u32, ExecError> {
        primitives::sync::lock_state(&self.migrate_calls).push(from);
        if self.migrate_fails {
            return Err(ExecError::ModuleRejected("boom".to_string()));
        }
        Ok(self.version)
    }
    fn scheduled_halt_height(&self) -> Option<u64> {
        *primitives::sync::lock_state(&self.halt)
    }
    fn export_state(&self) -> Option<storage::Snapshot> {
        Some(storage::Snapshot {
            height: 0,
            entries: primitives::sync::lock_state(&self.kv).clone(),
        })
    }
    fn inspect_state(&self, snapshot: &storage::Snapshot) -> Result<Hash, storage::SnapshotError> {
        // `kv` is test scratch that `state_root` does not commit —
        // the claimed root is the constant. Still validate the
        // payload is well-formed (sorted, unique keys) so the
        // strict path exercises real checks.
        for w in snapshot.entries.windows(2) {
            if w[0].0 >= w[1].0 {
                return Err(storage::SnapshotError::Malformed);
            }
        }
        Ok(self.state_root())
    }
    fn import_state(&self, snapshot: &storage::Snapshot) -> Result<(), storage::SnapshotError> {
        *primitives::sync::lock_state(&self.kv) = snapshot.entries.clone();
        Ok(())
    }
}

/// The snapshot must carry the format version and each module's
/// declared schema version — the importer needs both to decide
/// which `migrate(from)` calls to run.
#[test]
fn snapshot_export_records_format_and_module_versions() {
    let mut executor = test_executor(100);
    executor.register_module(VersionedModule::new(3) as Arc<dyn Module>);
    let snapshot = executor.export_snapshot();
    assert_eq!(snapshot.version, SNAPSHOT_FORMAT_VERSION);
    assert_eq!(snapshot.module_versions, vec![3]);
}

/// A v1 (pre-versioning) snapshot payload must still decode:
/// the version tail is absent → version 1, empty `module_versions`.
#[test]
fn snapshot_v1_payload_decodes_as_version_one() {
    let mut executor = test_executor(100);
    executor.register_module(Arc::new(CounterModule::new()));
    let snapshot = executor.export_snapshot();
    let mut buf = Vec::new();
    codec::Encode::encode(&snapshot, &mut buf);
    // Strip the v2 tail: u32 version + u32 count + N*u32 = 8 + 4 bytes.
    let v1_len = buf.len() - 8 - 4;
    let v1_bytes = &buf[..v1_len];
    let mut reader = codec::Reader::new(v1_bytes);
    let decoded =
        <ExecutorSnapshot as codec::Decode>::decode(&mut reader).expect("v1 payload must decode");
    assert_eq!(decoded.version, 1, "absent tail reads as format v1");
    assert!(decoded.module_versions.is_empty());
    assert_eq!(decoded.height, snapshot.height);
}

/// A forged count prefix must not become an allocation size:
/// `decode` reserves at most `remaining / min-wire-size` slots
/// per section, so a `u32::MAX` count fails with a plain decode
/// error instead of reserving ~hundreds of GiB and killing the
/// importer. Covers every counted section: roots, state,
/// nonces, versions.
#[test]
fn snapshot_decode_bounds_count_driven_allocations() {
    // An empty executor (no modules, no nonces) produces a
    // layout with fixed count offsets:
    //   [0..8)   height
    //   [8..40)  state_root
    //   [40..44) roots_count   = 0
    //   [44..48) state_count   = 0
    //   [48..52) nonces_count  = 0
    //   [52..84) nonce_root
    //   [84..88) version
    //   [88..92) versions_count = 0
    let executor = test_executor(100);
    let snapshot = executor.export_snapshot();
    assert!(snapshot.module_roots.is_empty() && snapshot.module_state.is_empty());
    let mut buf = Vec::new();
    codec::Encode::encode(&snapshot, &mut buf);
    assert_eq!(buf.len(), 92, "empty snapshot layout must be the fixed size asserted below");

    for offset in [40usize, 44, 48, 88] {
        let mut forged = buf.clone();
        forged[offset..offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        let mut reader = codec::Reader::new(&forged);
        assert!(
            <ExecutorSnapshot as codec::Decode>::decode(&mut reader).is_err(),
            "count field at offset {offset} inflated to u32::MAX must fail decode"
        );
    }
}

/// A snapshot from a newer binary must be refused — importing
/// state it can't interpret would corrupt the validator.
#[test]
fn snapshot_newer_version_rejected() {
    let mut executor = test_executor(100);
    executor.register_module(Arc::new(CounterModule::new()));
    let mut snapshot = executor.export_snapshot();
    snapshot.version = SNAPSHOT_FORMAT_VERSION + 1;
    let mut executor2 = test_executor(100);
    executor2.register_module(Arc::new(CounterModule::new()));
    match executor2.import_snapshot(&snapshot) {
        Err(SnapshotImportError::UnsupportedVersion { snapshot, supported }) => {
            assert_eq!(snapshot, SNAPSHOT_FORMAT_VERSION + 1);
            assert_eq!(supported, SNAPSHOT_FORMAT_VERSION);
        }
        other => panic!("expected UnsupportedVersion, got {other:?}"),
    }
}

/// A module whose snapshot version trails its declared version
/// must get `migrate(from)` called with the recorded version.
#[test]
fn snapshot_import_runs_module_migration() {
    let mut executor = test_executor(100);
    executor.register_module(VersionedModule::new(1) as Arc<dyn Module>);
    let mut snapshot = executor.export_snapshot();
    // Forge an old-schema record: the importer declares v2 but
    // the snapshot's state was written at v1.
    snapshot.module_versions = vec![1];

    let module = VersionedModule::new(2);
    let spy = Arc::clone(&module);
    let mut executor2 = test_executor(100);
    executor2.register_module(module as Arc<dyn Module>);
    executor2.import_snapshot(&snapshot).expect("import + migrate must succeed");
    assert_eq!(
        *primitives::sync::lock_state(&spy.migrate_calls),
        vec![1],
        "migrate must be called with the snapshot's recorded version"
    );
}

/// A failing migration must fail the whole import — a partially
/// migrated state set is worse than no import at all.
#[test]
fn snapshot_import_fails_closed_on_migration_error() {
    let mut executor = test_executor(100);
    executor.register_module(VersionedModule::new(1) as Arc<dyn Module>);
    let mut snapshot = executor.export_snapshot();
    snapshot.module_versions = vec![1];

    let module = VersionedModule {
        version: 2,
        halt: Mutex::new(None),
        migrate_calls: Mutex::new(Vec::new()),
        migrate_fails: true,
        kv: Mutex::new(Vec::new()),
    };
    let mut executor2 = test_executor(100);
    executor2.register_module(Arc::new(module) as Arc<dyn Module>);
    match executor2.import_snapshot(&snapshot) {
        Err(SnapshotImportError::MigrationFailed { module, from }) => {
            assert_eq!(module, "versioned");
            assert_eq!(from, 1);
        }
        other => panic!("expected MigrationFailed, got {other:?}"),
    }
}

// ── Strict snapshot import (audit 3.2) ─────────────────────────
//
// A snapshot is untrusted input: every structural defect and every
// unproven claim must reject BEFORE any module mutates. These
// tests build the failing variants from a *valid* exported
// snapshot so the only difference is the defect under test.

/// Run one counter tx so the source module has non-fresh
/// committed state to carry across.
fn exec_one_tx(executor: &Executor) {
    let tx = make_tx(1, &[0xAA]);
    executor.finalize_block(&FinalizedBlock {
        context: types::BlockContext::default(),
        height: Height::new(0),
        txs: vec![tx],
        signers: vec![],
    });
}

/// The name in `module_roots` binds the payload to the module —
/// a forged name (a different chain's ordering) must reject.
#[test]
fn snapshot_import_rejects_module_name_mismatch() {
    let mut executor = test_executor(100);
    executor.register_module(Arc::new(CounterModule::new()));
    exec_one_tx(&executor);
    let mut snapshot = executor.export_snapshot();
    // The root aggregate commits only the root values, not names,
    // so a name swap does not disturb `state_root`.
    snapshot.module_roots[0].0 = "not-counter".to_string();

    let mut executor2 = test_executor(100);
    executor2.register_module(Arc::new(CounterModule::new()));
    match executor2.import_snapshot(&snapshot) {
        Err(SnapshotImportError::ModuleNameMismatch { index, snapshot, registered }) => {
            assert_eq!(index, 0);
            assert_eq!(snapshot, "not-counter");
            assert_eq!(registered, "counter");
        }
        other => panic!("expected ModuleNameMismatch, got {other:?}"),
    }
}

/// A `module_state` shorter than the module list is malformed —
/// the tail modules' state was never committed.
#[test]
fn snapshot_import_rejects_module_state_count_mismatch() {
    let mut executor = test_executor(100);
    executor.register_module(Arc::new(CounterModule::new()));
    exec_one_tx(&executor);
    let mut snapshot = executor.export_snapshot();
    snapshot.module_state.clear(); // module claims state, none carried

    let mut executor2 = test_executor(100);
    executor2.register_module(Arc::new(CounterModule::new()));
    match executor2.import_snapshot(&snapshot) {
        Err(SnapshotImportError::MissingModuleState { module }) => {
            assert_eq!(module, "counter");
        }
        other => panic!("expected MissingModuleState, got {other:?}"),
    }
}

/// A `None` payload for a stateful module is incomplete state,
/// not a sparse encoding.
#[test]
fn snapshot_import_rejects_dropped_module_state() {
    let mut executor = test_executor(100);
    executor.register_module(Arc::new(CounterModule::new()));
    exec_one_tx(&executor);
    let mut snapshot = executor.export_snapshot();
    snapshot.module_state[0] = None;

    let mut executor2 = test_executor(100);
    executor2.register_module(Arc::new(CounterModule::new()));
    match executor2.import_snapshot(&snapshot) {
        Err(SnapshotImportError::MissingModuleState { module }) => {
            assert_eq!(module, "counter");
        }
        other => panic!("expected MissingModuleState, got {other:?}"),
    }
}

/// A payload supplied for a stateless module is uninterpretable —
/// it must be rejected, not silently ignored.
#[test]
fn snapshot_import_rejects_unexpected_module_state() {
    let mut executor = test_executor(100);
    executor.register_module(Arc::new(SelfAuthModule));
    let mut snapshot = executor.export_snapshot();
    assert!(snapshot.module_state[0].is_none());
    snapshot.module_state[0] =
        Some(storage::Snapshot { height: 0, entries: vec![(Hash([0; 32]), vec![1])] });

    let mut executor2 = test_executor(100);
    executor2.register_module(Arc::new(SelfAuthModule));
    match executor2.import_snapshot(&snapshot) {
        Err(SnapshotImportError::UnexpectedModuleState { module }) => {
            assert_eq!(module, "selfauth");
        }
        other => panic!("expected UnexpectedModuleState, got {other:?}"),
    }
}

/// A payload that fails the module's own decode must surface as
/// malformed during the verify pass.
#[test]
fn snapshot_import_rejects_malformed_module_state() {
    let mut executor = test_executor(100);
    executor.register_module(Arc::new(CounterModule::new()));
    exec_one_tx(&executor);
    let mut snapshot = executor.export_snapshot();
    // Corrupt the counter's blob: wrong length value.
    snapshot.module_state[0] =
        Some(storage::Snapshot { height: 0, entries: vec![(Hash([0xEE; 32]), vec![1, 2, 3])] });

    let mut executor2 = test_executor(100);
    executor2.register_module(Arc::new(CounterModule::new()));
    match executor2.import_snapshot(&snapshot) {
        Err(SnapshotImportError::MalformedModuleState { module }) => {
            assert_eq!(module, "counter");
        }
        other => panic!("expected MalformedModuleState, got {other:?}"),
    }
}

/// A claimed module root that doesn't match the staged payload's
/// decoded root must reject — the claim is never trusted over
/// the data.
#[test]
fn snapshot_import_rejects_forged_module_root() {
    let mut executor = test_executor(100);
    executor.register_module(Arc::new(CounterModule::new()));
    exec_one_tx(&executor);
    let mut snapshot = executor.export_snapshot();
    // Forge the claimed root, then re-fix the aggregate so only
    // the per-module claim is wrong.
    snapshot.module_roots[0].1 = Hash([0x99; 32]);
    snapshot.state_root =
        canonical_state_root(snapshot.module_roots.iter().map(|(_, r)| *r), snapshot.nonce_root);

    let mut executor2 = test_executor(100);
    executor2.register_module(Arc::new(CounterModule::new()));
    match executor2.import_snapshot(&snapshot) {
        Err(SnapshotImportError::ModuleRootMismatch { module, expected, actual }) => {
            assert_eq!(module, "counter");
            assert_eq!(expected, Hash([0x99; 32]));
            assert_eq!(actual, Hash([1; 32]), "the staged count is 1");
        }
        other => panic!("expected ModuleRootMismatch, got {other:?}"),
    }
}

/// Verify-before-mutate: a corrupt payload for the SECOND module
/// must leave the FIRST module untouched — no module state may be
/// installed until every module's payload verifies.
#[test]
fn snapshot_import_verifies_all_modules_before_mutating() {
    let mut executor = test_executor(100);
    let c1 = Arc::new(CounterModule::new());
    let c2 = Arc::new(CounterModule::other());
    executor.register_module(c1.clone());
    executor.register_module(c2.clone());
    exec_one_tx(&executor);
    let mut snapshot = executor.export_snapshot();
    // Corrupt only the second module's payload.
    snapshot.module_state[1] =
        Some(storage::Snapshot { height: 0, entries: vec![(Hash([0xEF; 32]), vec![0xDE, 0xAD])] });

    let d1 = Arc::new(CounterModule::new());
    let d2 = Arc::new(CounterModule::other());
    let mut executor2 = test_executor(100);
    executor2.register_module(d1.clone());
    executor2.register_module(d2.clone());
    assert!(
        executor2.import_snapshot(&snapshot).is_err(),
        "a malformed payload must fail the import"
    );
    assert_eq!(
        *primitives::sync::lock_state(&d1.count),
        0,
        "module 0 must not be mutated while module 1's payload is unproven"
    );
    assert_eq!(
        *primitives::sync::lock_state(&d2.count),
        0,
        "module 1 must not be mutated by a malformed payload"
    );
}

/// Metadata-only import is complete only for an executor whose
/// modules are all stateless — then it applies cleanly.
#[test]
fn snapshot_import_metadata_only_with_stateless_modules() {
    let mut executor = test_executor(100);
    executor.register_module(Arc::new(SelfAuthModule));
    executor.finalize_block(&FinalizedBlock {
        context: types::BlockContext::default(),
        height: Height::new(0),
        txs: vec![],
        signers: vec![],
    });
    let mut snapshot = executor.export_snapshot();
    snapshot.module_state.clear();

    let mut executor2 = test_executor(100);
    executor2.register_module(Arc::new(SelfAuthModule));
    executor2.import_snapshot(&snapshot).expect("stateless modules need no payloads");
}

/// Past the scheduled halt, `execute_block` must return the
/// frozen root and run no handlers — every replica stops
/// mutating state at the same height.
#[test]
fn halt_height_freezes_execution() {
    let mut executor = test_executor(100);
    let counter = Arc::new(CounterModule::new());
    executor.register_module(counter.clone());
    let halter = VersionedModule::new(1);
    *primitives::sync::lock_state(&halter.halt) = Some(1);
    executor.register_module(halter as Arc<dyn Module>);

    // Height 1 executes normally (halt = last live height).
    let tx = make_tx(1, &[0]);
    executor.ingest_tx(tx);
    let budget = types::BlockBudget { max_bytes: 1 << 20, max_gas: 1 << 30 };
    let proposal = executor.prepare_proposal(&budget);
    executor.finalize_block(&FinalizedBlock {
        context: types::BlockContext::default(),
        height: Height::new(1),
        txs: proposal.txs,
        signers: Vec::new(),
    });
    let live_root = executor.current_state_root();
    let live_count = *primitives::sync::lock_state(&counter.count);

    // Height 2 is past the halt: state must not change even
    // though the block carries a tx.
    let block2 = FinalizedBlock {
        context: types::BlockContext::default(),
        height: Height::new(2),
        txs: vec![make_tx(1, &[1])],
        signers: Vec::new(),
    };
    executor.finalize_block(&block2);
    assert_eq!(executor.current_state_root(), live_root, "state must freeze at halt");
    assert_eq!(
        *primitives::sync::lock_state(&counter.count),
        live_count,
        "no handlers run past the halt"
    );
}

/// Past the halt, proposals carry no txs — the chain keeps
/// committing empty blocks so consensus stays live while
/// operators swap binaries.
#[test]
fn prepare_proposal_empty_past_halt() {
    let mut executor = test_executor(100);
    executor.register_module(Arc::new(CounterModule::new()));
    let halter = VersionedModule::new(1);
    *primitives::sync::lock_state(&halter.halt) = Some(0);
    executor.register_module(halter as Arc<dyn Module>);

    executor.ingest_tx(make_tx(1, &[0]));
    let budget = types::BlockBudget { max_bytes: 1 << 20, max_gas: 1 << 30 };
    let proposal = executor.prepare_proposal(&budget);
    assert!(proposal.txs.is_empty(), "no txs may be proposed past the halt");
}

// ---- Async execution lane tests ----
//
// `spawn_exec_lane` moves block execution onto a worker thread:
// `finalize_block` returns immediately, `attest_state` waits on
// the watermark only for heights the lane actually owes.

#[test]
fn exec_lane_executes_and_attests() {
    let mut executor = test_executor(100);
    executor.register_module(Arc::new(CounterModule::new()));
    let executor = Arc::new(executor);
    executor.spawn_exec_lane();

    // A real tx so the counter module's root is non-zero
    // (count=0 → Hash::ZERO, the same sentinel attest_state
    // returns for unexecuted heights — a zero-root block would
    // make this test vacuous).
    let block = FinalizedBlock {
        context: types::BlockContext::default(),
        height: Height::new(0),
        txs: vec![make_tx_with_nonce(1, &[7], 0)],
        signers: vec![],
    };
    executor.finalize_block(&block);

    // attest_state waits on the worker watermark and returns
    // the worker-computed root.
    let att = executor.attest_state(Height::new(0)).expect("executed");
    assert_eq!(att.height, Height::new(0));
    assert_ne!(att.root, Hash::ZERO, "worker must have executed the block");
    // attest_latest reads the watermark without blocking.
    let latest = executor.attest_latest().expect("executed");
    assert_eq!(latest.height, Height::new(0));
    assert_eq!(latest.root, att.root);
}

#[test]
fn exec_lane_matches_sync_roots() {
    // The lane must produce byte-identical state roots to the
    // synchronous path — same blocks, same order.
    let mut sync_exec = test_executor(100);
    sync_exec.register_module(Arc::new(CounterModule::new()));
    let mut async_exec = test_executor(100);
    async_exec.register_module(Arc::new(CounterModule::new()));
    let async_exec = Arc::new(async_exec);
    async_exec.spawn_exec_lane();

    for h in 0..5u64 {
        let block = FinalizedBlock {
            context: types::BlockContext::default(),
            height: Height::new(h),
            txs: vec![make_tx_with_nonce(1, &[u8::try_from(h).unwrap_or(0)], h)],
            signers: vec![],
        };
        sync_exec.finalize_block(&block);
        async_exec.finalize_block(&block);
    }
    for h in 0..5u64 {
        let sync_root = sync_exec.attest_state(Height::new(h)).expect("executed").root;
        let async_root = async_exec.attest_state(Height::new(h)).expect("executed").root;
        assert_eq!(sync_root, async_root, "height {h} root mismatch");
        assert_ne!(sync_root, Hash::ZERO);
    }
}

#[test]
fn attest_beyond_enqueued_does_not_block() {
    // attest_state for a height the lane never saw must return
    // `None` immediately — never wait on execution that isn't
    // coming.
    let mut executor = test_executor(100);
    executor.register_module(Arc::new(CounterModule::new()));
    let executor = Arc::new(executor);
    executor.spawn_exec_lane();
    executor.finalize_block(&FinalizedBlock {
        context: types::BlockContext::default(),
        height: Height::new(0),
        txs: vec![make_tx_with_nonce(1, &[1], 0)],
        signers: vec![],
    });
    executor.attest_state(Height::new(0)); // drain the lane

    // Run the attest on a helper thread with a hard deadline —
    // if the wait logic ever blocks on an unknown height this
    // test fails by timeout rather than hanging CI forever.
    let (tx, rx) = std::sync::mpsc::channel();
    let app = executor.clone();
    std::thread::spawn(move || {
        tx.send(app.attest_state(Height::new(99))).expect("send");
    });
    let att = rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("attest_state must not block on an unenqueued height");
    // An unenqueued height has no execution coming — `None`,
    // the explicit "not executed" signal.
    assert!(att.is_none());
}

/// `attest_state_bounded` must return `None` once `max_wait`
/// expires while the lane still owes the height — the vote path
/// withholds rather than stalls behind a lagging worker. The
/// gated module parks the worker mid-block, so the wait is real.
#[test]
fn attest_state_bounded_times_out_on_owed_height() {
    let mut executor = test_executor(100);
    let module = Arc::new(GatedModule {
        gate: std::sync::atomic::AtomicBool::new(false),
        calls: Mutex::new(0),
    });
    executor.register_module(module.clone() as Arc<dyn Module>);
    let executor = Arc::new(executor);
    executor.spawn_exec_lane();

    // h0 parks the worker inside the gate — enqueued but not
    // executed for as long as the gate stays shut.
    executor.finalize_block(&finalized_block(0, 4, 0));

    let start = std::time::Instant::now();
    let att = executor.attest_state_bounded(Height::new(0), std::time::Duration::from_millis(100));
    let elapsed = start.elapsed();
    assert!(att.is_none(), "an owed-but-unexecuted height times out to None");
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "the bounded wait must actually return — elapsed {elapsed:?}"
    );

    // Release the gate so the worker can drain; the next bounded
    // call returns the real root.
    module.gate.store(true, std::sync::atomic::Ordering::SeqCst);
    let att = executor
        .attest_state_bounded(Height::new(0), std::time::Duration::from_secs(5))
        .expect("executed after the gate opens");
    assert_ne!(att.root, Hash::ZERO);
}

/// A bounded attest that lands mid-wait returns the root — the
/// timeout is a ceiling, not a fixed delay.
#[test]
fn attest_state_bounded_returns_when_execution_lands() {
    let mut executor = test_executor(100);
    let module = Arc::new(GatedModule {
        gate: std::sync::atomic::AtomicBool::new(false),
        calls: Mutex::new(0),
    });
    executor.register_module(module.clone() as Arc<dyn Module>);
    let executor = Arc::new(executor);
    executor.spawn_exec_lane();
    executor.finalize_block(&finalized_block(0, 4, 0));

    // Open the gate shortly after the attest starts waiting.
    let releaser = module.clone();
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(50));
        releaser.gate.store(true, std::sync::atomic::Ordering::SeqCst);
    });

    let att = executor
        .attest_state_bounded(Height::new(0), std::time::Duration::from_secs(5))
        .expect("the root lands inside the wait window");
    assert_ne!(att.root, Hash::ZERO);
}

/// A module that panics inside `handle` exactly once — models a
/// worker-killing execution fault that replays cleanly when the
/// same committed block is re-executed later.
struct PanicOnceModule {
    /// Set until the first `handle` call detonates it.
    armed: std::sync::atomic::AtomicBool,
    /// Invocation count, for the post-recovery state root.
    calls: Mutex<u64>,
}

impl PanicOnceModule {
    fn new() -> Self {
        Self { armed: std::sync::atomic::AtomicBool::new(true), calls: Mutex::new(0) }
    }
}

impl Module for PanicOnceModule {
    fn name(&self) -> &'static str {
        "panic-once"
    }
    fn id(&self) -> u8 {
        2
    }
    fn begin_block(&self, _height: Height) {}
    fn handle(&self, _ctx: &TxContext, _msg: &[u8]) -> Result<Vec<Event>, ExecError> {
        assert!(
            !self.armed.swap(false, std::sync::atomic::Ordering::SeqCst),
            "panic-once: injected execution fault"
        );
        *primitives::sync::lock_state(&self.calls) += 1;
        Ok(vec![Event { module: "panic-once", kind: "call", data: vec![] }])
    }
    fn end_block(&self, _height: Height) -> Vec<Event> {
        Vec::new()
    }
    fn state_root(&self) -> Hash {
        // Non-zero once any call has landed (count 1 → byte 1).
        let c = *primitives::sync::lock_state(&self.calls);
        Hash([u8::try_from(c.max(1)).unwrap_or(0xff); 32])
    }
}

#[test]
fn exec_lane_death_unblocks_attest() {
    // A worker that dies mid-block must not leave `attest_state`
    // waiting forever: the lane's death is terminal, so the
    // attest for the lost height returns `None` (no root landed)
    // instead of blocking on a watermark that can never advance.
    let mut executor = test_executor(100);
    executor.register_module(Arc::new(PanicOnceModule::new()));
    let executor = Arc::new(executor);
    executor.spawn_exec_lane();

    // The panic tx kills the worker during block 0's execution.
    executor.finalize_block(&FinalizedBlock {
        context: types::BlockContext::default(),
        height: Height::new(0),
        txs: vec![make_tx_with_nonce(2, &[1], 0)],
        signers: vec![],
    });
    // Give the worker a beat to receive, panic, and unwind —
    // execution is microseconds; this margin only needs to
    // outlive thread scheduling.
    std::thread::sleep(std::time::Duration::from_millis(200));

    // attest_state on the dead lane's lost height must return —
    // on a helper thread with a hard deadline so a hang fails
    // by timeout rather than hanging CI forever.
    let (tx, rx) = std::sync::mpsc::channel();
    let app = executor.clone();
    std::thread::spawn(move || {
        tx.send(app.attest_state(Height::new(0))).expect("send");
    });
    let att = rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("attest_state must not hang on a dead execution lane");
    // The panicked block's root never landed — nothing executed.
    assert!(att.is_none(), "a height lost to a dead lane has no root to attest");
}

/// A module that mutates observable state BEFORE panicking —
/// the partial-application case the old `PanicOnceModule`
/// fixture could not express (it detonated before mutating, so
/// its replay was benign by construction). Here the mutation
/// lands first, so the block is provably half-applied when the
/// worker dies.
struct MutateThenPanicModule {
    /// Invocation count — the observable mutation proving
    /// execution began before the fault.
    calls: Mutex<u64>,
    /// Set until the first `handle` detonates it.
    armed: std::sync::atomic::AtomicBool,
}

impl Module for MutateThenPanicModule {
    fn name(&self) -> &'static str {
        "mutate-then-panic"
    }
    fn id(&self) -> u8 {
        3
    }
    fn begin_block(&self, _height: Height) {}
    fn handle(&self, _ctx: &TxContext, _msg: &[u8]) -> Result<Vec<Event>, ExecError> {
        // Mutation FIRST — the moment this lands the block is
        // partially applied, and replaying it would repeat it.
        *primitives::sync::lock_state(&self.calls) += 1;
        assert!(
            !self.armed.swap(false, std::sync::atomic::Ordering::SeqCst),
            "mutate-then-panic: injected mid-mutation fault"
        );
        Ok(vec![Event { module: "mutate-then-panic", kind: "call", data: vec![] }])
    }
    fn end_block(&self, _height: Height) -> Vec<Event> {
        Vec::new()
    }
    fn state_root(&self) -> Hash {
        let c = *primitives::sync::lock_state(&self.calls);
        Hash([u8::try_from(c.max(1)).unwrap_or(0xff); 32])
    }
}

#[test]
fn exec_lane_death_backfills_committed_blocks() {
    // A lane that dies mid-`execute_block` leaves a PARTIALLY
    // APPLIED block — replaying it would re-run fees, nonces,
    // and module mutations on already-mutated state. The backlog
    // drain must fail closed (panic) instead of re-executing:
    // recovery belongs to durable state at restart, not to a
    // blind in-process replay.
    let mut executor = test_executor(100);
    executor.register_module(Arc::new(PanicOnceModule::new()));
    let executor = Arc::new(executor);
    executor.spawn_exec_lane();

    // Block 0 kills the worker mid-execution.
    executor.finalize_block(&FinalizedBlock {
        context: types::BlockContext::default(),
        height: Height::new(0),
        txs: vec![make_tx_with_nonce(2, &[1], 0)],
        signers: vec![],
    });
    std::thread::sleep(std::time::Duration::from_millis(200));

    // Block 1's finalize drives the backlog drain — which must
    // refuse to replay the partially applied block 0.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        executor.finalize_block(&FinalizedBlock {
            context: types::BlockContext::default(),
            height: Height::new(1),
            txs: vec![make_tx_with_nonce(2, &[2], 1)],
            signers: vec![],
        });
    }));
    let payload = result.expect_err("the drain must fail closed on a partially applied block");
    let msg = payload
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| payload.downcast_ref::<&str>().copied())
        .unwrap_or("");
    assert!(msg.contains("partially applied"), "halt message must name the cause, got: {msg}");
}

#[test]
fn exec_lane_death_mid_mutation_is_not_replayed() {
    // The `MutateThenPanicModule` lands its mutation BEFORE the
    // fault — block 0 is provably half-applied. The drain's
    // refusal must ALSO leave the mutation unreplayed: `calls`
    // stays at exactly 1 — a blind replay would have run the
    // same mutation a second time.
    let mut executor = test_executor(100);
    let module = Arc::new(MutateThenPanicModule {
        calls: Mutex::new(0),
        armed: std::sync::atomic::AtomicBool::new(true),
    });
    executor.register_module(module.clone() as Arc<dyn Module>);
    let executor = Arc::new(executor);
    executor.spawn_exec_lane();

    executor.finalize_block(&FinalizedBlock {
        context: types::BlockContext::default(),
        height: Height::new(0),
        txs: vec![make_tx_with_nonce(3, &[1], 0)],
        signers: vec![],
    });
    std::thread::sleep(std::time::Duration::from_millis(200));

    // The mutation landed before the panic — the block WAS
    // partially applied.
    assert_eq!(
        *primitives::sync::lock_state(&module.calls),
        1,
        "the pre-panic mutation must have landed exactly once"
    );

    // The drain refuses; the mutation is never replayed.
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        executor.finalize_block(&FinalizedBlock {
            context: types::BlockContext::default(),
            height: Height::new(1),
            txs: vec![make_tx_with_nonce(3, &[2], 1)],
            signers: vec![],
        });
    }));
    assert_eq!(
        *primitives::sync::lock_state(&module.calls),
        1,
        "a refused replay must not run the mutation a second time"
    );
}

/// The synchronous dispatch path must enforce the same
/// fail-closed contract as the exec lane: a module panic that
/// lands after earlier mutations leaves `in_flight` set with no
/// root, so the next `finalize_block` refuses to execute on top
/// of the half-applied block — replay belongs to durable-state
/// recovery at restart, not to in-process retry.
#[test]
fn sync_path_panic_mid_mutation_poisons_executor() {
    let mut executor = test_executor(100);
    let module = Arc::new(MutateThenPanicModule {
        calls: Mutex::new(0),
        armed: std::sync::atomic::AtomicBool::new(true),
    });
    executor.register_module(module.clone() as Arc<dyn Module>);
    // No exec lane — the default synchronous path.

    // Block 0: mutation lands, then the panic propagates through
    // `finalize_block` to the caller.
    let first = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        executor.finalize_block(&FinalizedBlock {
            context: types::BlockContext::default(),
            height: Height::new(0),
            txs: vec![make_tx_with_nonce(3, &[1], 0)],
            signers: vec![],
        });
    }));
    assert!(first.is_err(), "the module panic must propagate to the committer");
    assert_eq!(
        *primitives::sync::lock_state(&module.calls),
        1,
        "the pre-panic mutation landed — the block is partially applied"
    );

    // Block 1 must fail closed: replaying block 0 on top of the
    // surviving mutation would double-apply it. (The module is
    // disarmed, so a blind retry would even SUCCEED — silently
    // returning a root computed over double-applied state.)
    let second = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        executor.finalize_block(&FinalizedBlock {
            context: types::BlockContext::default(),
            height: Height::new(1),
            txs: vec![make_tx_with_nonce(3, &[2], 1)],
            signers: vec![],
        });
    }));
    let payload = second.expect_err("the sync path must fail closed on a partial apply");
    let msg = payload
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| payload.downcast_ref::<&str>().copied())
        .unwrap_or("");
    assert!(msg.contains("partially applied"), "halt message must name the cause, got: {msg}");
    assert_eq!(
        *primitives::sync::lock_state(&module.calls),
        1,
        "no mutation may replay on the poisoned executor"
    );
}

/// A module whose `handle` blocks until the test opens a gate —
/// models a slow worker so the lane's queue can be filled
/// deterministically. Spins on an atomic rather than a channel
/// so a single flag release unblocks every later call too.
struct GatedModule {
    /// Open when the test releases execution.
    gate: std::sync::atomic::AtomicBool,
    /// Invocation count, for post-drain assertions.
    calls: Mutex<u64>,
}

impl Module for GatedModule {
    fn name(&self) -> &'static str {
        "gated"
    }
    fn id(&self) -> u8 {
        4
    }
    fn begin_block(&self, _height: Height) {}
    fn handle(&self, _ctx: &TxContext, _msg: &[u8]) -> Result<Vec<Event>, ExecError> {
        while !self.gate.load(std::sync::atomic::Ordering::SeqCst) {
            std::hint::spin_loop();
        }
        *primitives::sync::lock_state(&self.calls) += 1;
        Ok(vec![Event { module: "gated", kind: "call", data: vec![] }])
    }
    fn end_block(&self, _height: Height) -> Vec<Event> {
        Vec::new()
    }
    fn state_root(&self) -> Hash {
        let c = *primitives::sync::lock_state(&self.calls);
        Hash([u8::try_from(c.max(1)).unwrap_or(0xff); 32])
    }
}

fn finalized_block(height: u64, module: u8, nonce: u64) -> FinalizedBlock {
    FinalizedBlock {
        context: types::BlockContext::default(),
        height: Height::new(height),
        txs: vec![make_tx_with_nonce(module, &[u8::try_from(height).unwrap_or(0xff)], nonce)],
        signers: vec![],
    }
}

#[test]
fn finalized_pruning_pins_unexecuted_heights() {
    // Retention bounds only the executed prefix: a committed
    // height without a state root is the drain's backlog and
    // must survive pruning no matter how far behind execution
    // falls.
    let executor = test_executor(100).with_history_retention(2);

    // Nothing executed: every committed height is unexecuted —
    // the pin holds all of them even past the window.
    for h in 0..4 {
        executor.insert_finalized(h, finalized_block(h, 1, h));
    }
    assert_eq!(
        primitives::sync::lock_state(&executor.finalized).len(),
        4,
        "unexecuted heights must never be evicted"
    );

    // Mark 0–2 executed (in-order execution ⇒ rooted): they
    // become evictable; 3 and the new 4 stay pinned.
    {
        let (lock, _cv) = &*executor.exec_sync;
        primitives::sync::lock_state(lock).executed = Some(2);
    }
    executor.insert_finalized(4, finalized_block(4, 1, 4));
    let kept: Vec<u64> =
        primitives::sync::lock_state(&executor.finalized).keys().copied().collect();
    assert_eq!(kept, vec![3, 4], "only executed heights may be evicted");
}

#[test]
fn exec_lane_saturates_without_blocking() {
    // The lane must never stall the commit path: once the pending
    // deque crosses the saturation depth, `exec_saturated` reports
    // the backpressure to the engine (which withholds votes and
    // defers commits) while `finalize_block` itself keeps returning
    // immediately — a committed block can never be dropped, so the
    // deque is unbounded and the flag is the bound. The old bounded
    // channel made a backed-up lane freeze the whole consensus pump.
    let mut executor = test_executor(100).with_history_retention(5);
    // saturation depth = min(EXEC_LANE_DEPTH, retention - 1) = 4.
    let module = Arc::new(GatedModule {
        gate: std::sync::atomic::AtomicBool::new(false),
        calls: Mutex::new(0),
    });
    executor.register_module(module.clone() as Arc<dyn Module>);
    let executor = Arc::new(executor);
    executor.spawn_exec_lane();

    // h0 reaches the worker and parks inside the gate.
    executor.finalize_block(&finalized_block(0, 4, 0));
    std::thread::sleep(std::time::Duration::from_millis(100));

    // h1..h4 fill the pending deque up to the threshold — the flag
    // must still be clear at exactly `depth` entries.
    for h in 1..=4u64 {
        executor.finalize_block(&finalized_block(h, 4, h));
    }
    assert!(!executor.exec_saturated(), "a deque at the threshold must not yet report saturation");

    // h5 pushes the deque past the threshold. `finalize_block` must
    // still return immediately — the hand-off never blocks.
    let done = std::sync::mpsc::channel::<()>();
    let exec2 = executor.clone();
    let join = std::thread::spawn(move || {
        exec2.finalize_block(&finalized_block(5, 4, 5));
        let _ = done.0.send(());
    });
    done.1
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("finalize must not block behind a saturated lane");
    join.join().expect("finalize thread must not panic");
    assert!(
        executor.exec_saturated(),
        "crossing the threshold must raise the engine-facing signal"
    );

    // Release the worker: the backlog drains in commit order, every
    // block executes exactly once, and the flag clears only once the
    // deque is empty.
    module.gate.store(true, std::sync::atomic::Ordering::SeqCst);
    executor.wait_exec_idle();
    assert_eq!(
        *primitives::sync::lock_state(&module.calls),
        6,
        "every committed block executed exactly once"
    );
    assert!(!executor.exec_saturated(), "a fully drained lane must clear the saturation signal");
}

// ---- Mempool finality-custody tests ----

/// A tx in a proposal that never commits must stay re-proposable:
/// `select` is a peek, so losing the round doesn't lose the tx.
/// The old remove-on-select path drained the pool the moment a
/// proposal was built — a losing proposal erased its txs forever.
///
/// Under in-flight marking the tx is not re-selected *while its
/// proposal's position is open*: a pipelined proposal carrying it
/// again would commit as a deterministic nonce skip. It re-proposes
/// once the next commit resolves the position — a one-position
/// delay, never a loss. (The OAI has no "proposal aborted" signal,
/// so commit is the earliest sound release point.)
#[test]
fn uncommitted_proposal_keeps_txs() {
    let mut executor = test_executor(100);
    executor.register_module(Arc::new(CounterModule::new()));
    executor.ingest_tx(make_tx(1, &[42]));
    let budget = types::BlockBudget { max_bytes: 1 << 20, max_gas: 1 << 30 };
    let first = executor.prepare_proposal(&budget);
    assert_eq!(first.txs.len(), 1);
    // The position is still open: the in-flight tx must not
    // duplicate into the next proposal — that duplicate would
    // commit as a nonce skip and waste the slot.
    let second = executor.prepare_proposal(&budget);
    assert!(second.txs.is_empty(), "in-flight txs are not re-selected");
    assert_eq!(executor.mempool_len(), 1, "the tx stays pooled");
    // A commit resolves the open position — even one carrying no
    // txs — and the pooled tx becomes selectable again.
    executor.finalize_block(&FinalizedBlock {
        context: types::BlockContext::default(),
        height: Height::new(0),
        txs: Vec::new(),
        signers: Vec::new(),
    });
    let third = executor.prepare_proposal(&budget);
    assert_eq!(third.txs, first.txs, "the released tx re-proposes once its position resolves");
}

/// The mirror image: txs DO leave the pool — but only when a
/// block finalizes them.
#[test]
fn committed_txs_leave_pool_at_finalize() {
    let mut executor = test_executor(100);
    executor.register_module(Arc::new(CounterModule::new()));
    executor.ingest_tx(make_tx(1, &[42]));
    let budget = types::BlockBudget { max_bytes: 1 << 20, max_gas: 1 << 30 };
    let proposal = executor.prepare_proposal(&budget);
    assert_eq!(proposal.txs.len(), 1);
    // Before finality the tx is still pooled.
    assert_eq!(executor.mempool_len(), 1);
    executor.finalize_block(&FinalizedBlock {
        context: types::BlockContext::default(),
        height: Height::new(0),
        txs: proposal.txs,
        signers: Vec::new(),
    });
    assert_eq!(executor.mempool_len(), 0, "committed txs leave the pool");
    assert!(
        executor.prepare_proposal(&budget).txs.is_empty(),
        "nothing may be re-proposed after commit"
    );
}

/// Candidates the proposal-time gas filter skips must survive
/// for the next block — previously they were silently deleted
/// with the rest of the selection.
#[test]
fn gas_filtered_candidates_stay_pooled() {
    let mut executor =
        test_executor_with_config(100, DEFAULT_PARALLEL_THRESHOLD).with_gas_limit(2500);
    executor.register_module(Arc::new(CounterModule::new()));
    // Four ~1001-gas txs; only 2 fit under a 2500 cap per block.
    for n in 0..4u64 {
        let tx = make_tx_with_nonce(1, &[u8::try_from(n).unwrap_or(0xff)], n);
        assert!(matches!(executor.ingest_tx(tx), MempoolAck::Accepted));
    }
    let budget = types::BlockBudget { max_bytes: 1 << 20, max_gas: 1 << 30 };
    let first = executor.prepare_proposal(&budget);
    assert_eq!(first.txs.len(), 2);
    // Committing the first two leaves the filtered two pooled —
    // they fill the next block exactly.
    executor.finalize_block(&FinalizedBlock {
        context: types::BlockContext::default(),
        height: Height::new(0),
        txs: first.txs,
        signers: Vec::new(),
    });
    let second = executor.prepare_proposal(&budget);
    assert_eq!(second.txs.len(), 2, "filtered candidates fill the next block");
}

/// `ingest_tx_batch` must map pool rejections back to the
/// tx's slot in the *caller's* batch — the filtered `accepted`
/// vec's position used to be used as the index, so a rejection
/// overwrote an unrelated earlier `Accepted` result and left the
/// actually-rejected tx acknowledged.
#[test]
fn batch_acks_map_to_original_indices() {
    let mut executor = test_executor(100);
    executor.register_module(Arc::new(CounterModule::new()));
    let good = make_tx(1, &[42]);
    let results = executor.ingest_tx_batch(vec![
        TxBytes::new(vec![1, 2, 3]), // malformed — rejected in validation
        good.clone(),                // accepted
        good,                        // duplicate — rejected by the pool
    ]);
    assert_eq!(results.len(), 3);
    assert!(matches!(results[0], MempoolAck::Rejected { .. }), "malformed tx rejected");
    assert!(
        matches!(results[1], MempoolAck::Accepted),
        "the valid tx must be acknowledged Accepted — not clobbered by the duplicate's rejection"
    );
    assert!(
        matches!(results[2], MempoolAck::Rejected { .. }),
        "the duplicate must be the one reported Rejected"
    );
}

/// Finalized outcomes distinguish executed txs from gate-skipped
/// ones — the record a settlement client waits on. Mempool
/// acceptance alone must never read as "settled": these txs are
/// hand-built into the block so the gate-skips are exercised at
/// execution time, exactly where they occur in production.
#[test]
fn tx_outcome_records_executed_and_skipped() {
    let mut executor = test_executor(100);
    executor.register_module(Arc::new(CounterModule::new()));

    let good = make_tx_with_nonce(1, &[42], 0);
    let stale = make_tx_with_nonce(1, &[7], 7);
    let unknown = make_tx(99, &[1]);
    let block = FinalizedBlock {
        context: types::BlockContext::default(),
        height: Height::new(0),
        txs: vec![good.clone(), stale.clone(), unknown.clone()],
        signers: vec![],
    };
    executor.finalize_block(&block);

    let h = |tx: &TxBytes| Hasher::hash_one(Domain::Transaction, tx.as_bytes());
    match executor.tx_outcome(&h(&good)) {
        Some(TxOutcome::Executed { events, error }) => {
            assert!(error.is_none(), "clean dispatch");
            assert_eq!(events.len(), 1, "the module's event is attached to the outcome");
        }
        other => panic!("expected Executed, got {other:?}"),
    }
    assert_eq!(
        executor.tx_outcome(&h(&stale)),
        Some(TxOutcome::Skipped { reason: TxSkipReason::StaleNonce }),
    );
    assert_eq!(
        executor.tx_outcome(&h(&unknown)),
        Some(TxOutcome::Skipped { reason: TxSkipReason::UnknownModule }),
    );
    // Only the executed tx consumed its sender's nonce — the
    // skips left the counter at the executed value.
    assert_eq!(executor.executed_nonce_of(&Address([0u8; 20])), 1);
    // A tx never proposed has no outcome — `None` is "in flight".
    assert!(executor.tx_outcome(&Hash::ZERO).is_none());
}

/// A provisional `Skipped` outcome is overwritten when the same
/// tx later executes — the gas-limit case in production — while
/// an `Executed` outcome is final and can never be rewritten by
/// a stale re-proposal's skip.
#[test]
fn tx_outcome_store_overwrite_semantics() {
    let mut store = TxOutcomeStore::default();
    let h = Hash([1u8; 32]);
    store.record(h, TxOutcome::Skipped { reason: TxSkipReason::GasLimit });
    // The tx lands in a later block — Executed supersedes.
    let executed = TxOutcome::Executed { events: vec![], error: None };
    store.record(h, executed.clone());
    assert_eq!(store.outcomes.get(&h), Some(&executed));
    // A stale re-proposal skipping afterwards cannot rewrite it.
    store.record(h, TxOutcome::Skipped { reason: TxSkipReason::StaleNonce });
    assert_eq!(store.outcomes.get(&h), Some(&executed), "Executed is final");
}

/// A module rejection is still an execution: the fee was charged
/// and the nonce consumed — the outcome records the error so a
/// submitter can tell a revert apart from a clean apply.
#[test]
fn tx_outcome_records_module_rejection() {
    /// A module whose `handle` always rejects.
    struct RejectingModule;
    impl Module for RejectingModule {
        fn name(&self) -> &'static str {
            "rejector"
        }
        fn id(&self) -> u8 {
            3
        }
        fn begin_block(&self, _height: Height) {}
        fn handle(&self, _ctx: &TxContext, _msg: &[u8]) -> Result<Vec<Event>, ExecError> {
            Err(ExecError::ModuleRejected("nope".to_string()))
        }
        fn end_block(&self, _height: Height) -> Vec<Event> {
            Vec::new()
        }
        fn state_root(&self) -> Hash {
            Hash::ZERO
        }
    }

    let mut executor = test_executor(100);
    executor.register_module(Arc::new(RejectingModule));
    let tx = make_tx_with_nonce(3, &[1], 0);
    let block = FinalizedBlock {
        context: types::BlockContext::default(),
        height: Height::new(0),
        txs: vec![tx.clone()],
        signers: vec![],
    };
    executor.finalize_block(&block);

    let h = Hasher::hash_one(Domain::Transaction, tx.as_bytes());
    match executor.tx_outcome(&h) {
        Some(TxOutcome::Executed { events, error }) => {
            assert!(events.is_empty());
            assert!(error.unwrap_or_default().contains("nope"));
        }
        other => panic!("expected Executed-with-error, got {other:?}"),
    }
    // The rejection still consumed the nonce — a revert, not a
    // skip.
    assert_eq!(executor.executed_nonce_of(&Address([0u8; 20])), 1);
}

// ── Cross-module ordering regression fixtures — committed block
//    order, not module-id order, decides execution. ────────────

/// A ledger both fixture modules share — the test-side analogue
/// of the real EVM account store every module settles against.
type SharedLedger = Arc<Mutex<HashMap<Address, u64>>>;

/// Module id 7: credits `Address([payload[0]; 20])` with
/// `payload[1]` units. Deliberately a *higher* module id than
/// `CounterModule` (1) — under sorted-module grouping the funder
/// ran *after* the counter regardless of block order.
struct FunderModule {
    ledger: SharedLedger,
}

impl Module for FunderModule {
    fn name(&self) -> &'static str {
        "funder"
    }
    fn id(&self) -> u8 {
        7
    }
    fn begin_block(&self, _height: Height) {}
    fn handle(&self, _ctx: &TxContext, msg: &[u8]) -> Result<Vec<Event>, ExecError> {
        if msg.len() >= 2 {
            let mut ledger = primitives::sync::lock_state(&self.ledger);
            *ledger.entry(Address([msg[0]; 20])).or_insert(0) += u64::from(msg[1]);
        }
        Ok(vec![Event { module: "funder", kind: "funded", data: vec![] }])
    }
    fn end_block(&self, _height: Height) -> Vec<Event> {
        Vec::new()
    }
    fn state_root(&self) -> Hash {
        Hash::ZERO
    }
}

/// Fee collector (id 9) that debits the shared ledger — a charge
/// fails when the sender's balance is short, so tests can observe
/// *when* the charge ran relative to other txs' effects.
struct LedgerFeeCollector {
    ledger: SharedLedger,
}

impl Module for LedgerFeeCollector {
    fn name(&self) -> &'static str {
        "ledgerfeecollector"
    }
    fn id(&self) -> u8 {
        9
    }
    fn begin_block(&self, _height: Height) {}
    fn handle(&self, _ctx: &TxContext, _msg: &[u8]) -> Result<Vec<Event>, ExecError> {
        Ok(vec![])
    }
    fn end_block(&self, _height: Height) -> Vec<Event> {
        Vec::new()
    }
    fn state_root(&self) -> Hash {
        Hash::ZERO
    }
    fn charge_fee(&self, ctx: &TxContext) -> Result<(), ExecError> {
        let mut ledger = primitives::sync::lock_state(&self.ledger);
        let balance = ledger.entry(ctx.sender).or_insert(0);
        if *balance < ctx.fee {
            return Err(ExecError::ModuleRejected("insufficient fee balance".to_string()));
        }
        *balance -= ctx.fee;
        Ok(())
    }
}

fn ordering_executor(ledger: &SharedLedger) -> (Executor, Arc<CounterModule>) {
    let mut executor = test_executor(100);
    let counter = Arc::new(CounterModule::new());
    executor.register_module(counter.clone());
    executor.register_module(Arc::new(FunderModule { ledger: ledger.clone() }));
    executor.register_module(Arc::new(LedgerFeeCollector { ledger: ledger.clone() }));
    executor.set_fee_module(9);
    (executor, counter)
}

/// Finalize `txs` in the given order — the committed order is the
/// semantic under test, so blocks are built directly rather than
/// routed through `prepare_proposal` (whose fee-priority mempool
/// ordering is a separate, legitimate concern).
fn run_block(executor: &Executor, txs: Vec<TxBytes>) {
    executor.finalize_block(&FinalizedBlock {
        context: types::BlockContext::default(),
        height: Height::new(0),
        txs,
        signers: Vec::new(),
    });
}

/// The audit's core case: a tx in a *higher-numbered* module
/// (funder, id 7) credits the sender of a *lower-numbered*
/// module's tx (counter, id 1). Committed order is [funder,
/// counter] — sequential execution funds sender 9 before its
/// fee is charged. The old sort-by-module grouping ran the
/// counter's group first and charged fees before ANY module
/// executed — this tx was skipped either way. Now it runs.
#[test]
fn cross_module_funding_visible_to_later_fee_charge() {
    let ledger: SharedLedger = Arc::new(Mutex::new(HashMap::new()));
    let (executor, counter) = ordering_executor(&ledger);

    // Funder tx (sender 8, fee 0) credits sender 9 with 100 —
    // committed BEFORE the counter tx.
    let funder = make_tx_with_fee_and_sender(7, &[9, 100], 0, 0, 8);
    // Counter tx (sender 9, fee 100) — spends exactly what the
    // funder grants.
    let counter_tx = make_tx_with_fee_and_sender(1, &[1], 0, 100, 9);
    run_block(&executor, vec![funder, counter_tx]);

    assert_eq!(
        *primitives::sync::lock_state(&counter.count),
        1,
        "the counter tx must execute — its sender was funded earlier in the block"
    );
    assert_eq!(
        primitives::sync::lock_state(&ledger)[&Address([9u8; 20])],
        0,
        "the 100-unit fee was charged against the funding"
    );
}

/// The reverse order proves block order — not module order —
/// decides: counter (id 1) before funder (id 7), so the fee
/// charge fails on the empty balance even though the funder
/// runs later in the same block.
#[test]
fn later_module_funding_does_not_help_earlier_tx() {
    let ledger: SharedLedger = Arc::new(Mutex::new(HashMap::new()));
    let (executor, counter) = ordering_executor(&ledger);

    // Counter tx FIRST (sender 9 unfunded, fee 100 → charge fails).
    let counter_tx = make_tx_with_fee_and_sender(1, &[1], 0, 100, 9);
    // Funder SECOND — too late to help.
    let funder = make_tx_with_fee_and_sender(7, &[9, 100], 0, 0, 8);
    run_block(&executor, vec![counter_tx, funder]);

    assert_eq!(
        *primitives::sync::lock_state(&counter.count),
        0,
        "the counter tx must be skipped — its fee preceded the funding"
    );
    assert_eq!(
        primitives::sync::lock_state(&ledger)[&Address([9u8; 20])],
        100,
        "the funder still executed — its own fee was 0"
    );
}

/// A dispatch-time fee failure must not consume the nonce:
/// sequential semantics skip the failed tx AND everything behind
/// it in the sender's chain (the gap is unreachable), while the
/// executed-nonce marker stays retryable.
#[test]
fn fee_failure_rewinds_sender_nonce_chain() {
    let ledger: SharedLedger = Arc::new(Mutex::new(HashMap::new()));
    let (executor, counter) = ordering_executor(&ledger);

    // Sender 9: nonce 0 fee 100 (fails — empty balance), nonce 1
    // fee 0 (would charge fine — but the chain is broken).
    let head = make_tx_with_fee_and_sender(1, &[1], 0, 100, 9);
    let next = make_tx_with_fee_and_sender(1, &[1], 1, 0, 9);
    run_block(&executor, vec![head, next]);

    assert_eq!(
        *primitives::sync::lock_state(&counter.count),
        0,
        "neither tx executes — the chain broke at nonce 0"
    );
    assert_eq!(
        executor.executed_nonce_of(&Address([9u8; 20])),
        0,
        "nonce 0 stays unconsumed — the failed tx is retryable"
    );
}

// ---- certified-repair import (`Executor::repair_import_snapshot`) ----
//
// The repair path is the in-process half of divergence recovery:
// a verified peer snapshot replaces the diverged base, tainted
// post-base state is purged, and the still-committed tail replays
// on the verified base. These tests pin the mechanics: what is
// rebuilt, what is refused, and what watermarks resume.

/// Build a committed block at `height` carrying `txs` — the shape
/// `finalize_block` consumes, without routing through the mempool
/// (the committed order is the semantic under test).
fn repair_block(height: u64, txs: Vec<TxBytes>) -> FinalizedBlock {
    FinalizedBlock {
        context: types::BlockContext::default(),
        height: Height::new(height),
        txs,
        signers: Vec::new(),
    }
}

#[test]
fn repair_import_rebuilds_on_verified_snapshot_base() {
    // Divergence model: committed history is IDENTICAL on both
    // sides (consensus finalizes the same txs — the divergence is
    // in the execution *result*). The diverged node executed
    // blocks 0..=2 correctly, then its module state was corrupted
    // post-execution — exactly what a verified repair must undo.
    let mut diverged = test_executor(100);
    let counter = Arc::new(CounterModule::new());
    diverged.register_module(counter.clone());
    // Blocks 0,1: the canonical history the peer also executed.
    for h in 0..2u64 {
        diverged.finalize_block(&repair_block(h, vec![make_tx_with_nonce(1, &[9], h)]));
    }
    // Block 2: the still-committed tail the peer snapshot does not
    // cover — two txs, so honest replay lands the counter at 4.
    diverged.finalize_block(&repair_block(
        2,
        vec![make_tx_with_nonce(1, &[1], 2), make_tx_with_nonce(1, &[2], 3)],
    ));
    diverged.wait_exec_idle();
    assert_eq!(*primitives::sync::lock_state(&counter.count), 4, "setup: honest execution");
    // The honest tip root — captured BEFORE corruption — is what a
    // correct repair must reproduce.
    let honest_tip_root = diverged.state_root_at(2);
    // Corrupt post-execution state: the module's committed state
    // no longer produces the attested root — the divergence the
    // consensus side latched on.
    *primitives::sync::lock_state(&counter.count) = 99;

    // The certified peer: identical committed history through
    // height 1, so its snapshot carries the canonical base.
    let mut peer = test_executor(100);
    peer.register_module(Arc::new(CounterModule::new()));
    for h in 0..2u64 {
        peer.finalize_block(&repair_block(h, vec![make_tx_with_nonce(1, &[9], h)]));
    }
    peer.wait_exec_idle();
    let snapshot = peer.export_snapshot();
    assert_eq!(snapshot.height, 1, "peer tip is the snapshot base");

    let covered = diverged.repair_import_snapshot(&snapshot).expect("repair must import");
    assert_eq!(covered, 2, "snapshot base + replayed block 2");
    // The corrupted 99 is gone: peer base (2) + replayed block's
    // two txs rebuilt state, not patched it.
    assert_eq!(*primitives::sync::lock_state(&counter.count), 4);
    // The base root is the certified one, and the rebuilt tip root
    // equals what honest execution produced — repair reproduced
    // the canonical state, not merely *a* state.
    assert_eq!(diverged.state_root_at(1), snapshot.state_root);
    let rebuilt = diverged.state_root_at(2);
    assert_eq!(rebuilt, honest_tip_root, "rebuilt tip must match honest execution");
    // Attestation resumes at the rebuilt tip — `mark_repaired` on
    // the consensus side keys off exactly this attestation.
    let latest = diverged.attest_latest().expect("rebuilt state attests");
    assert_eq!(latest.height, Height::new(2));
    assert_eq!(latest.root, rebuilt);
}

#[test]
fn repair_import_rejects_history_gap_above_base() {
    // In-memory coverage must be contiguous from base+1: a missing
    // committed height cannot be skipped — replaying past the hole
    // produces a state no peer shares.
    let mut diverged = test_executor(100);
    diverged.register_module(Arc::new(CounterModule::new()));
    // Commit 0, 1, and 3 — height 2 never finalized locally (the
    // retention window or a crash could have dropped it).
    for (h, n) in [(0u64, 0u64), (1, 1), (3, 2)] {
        diverged.finalize_block(&repair_block(
            h,
            vec![make_tx_with_nonce(1, &[u8::try_from(h).unwrap_or(0xff)], n)],
        ));
    }
    diverged.wait_exec_idle();

    let mut peer = test_executor(100);
    peer.register_module(Arc::new(CounterModule::new()));
    peer.finalize_block(&repair_block(0, vec![make_tx_with_nonce(1, &[7], 0)]));
    peer.wait_exec_idle();
    let snapshot = peer.export_snapshot();
    assert_eq!(snapshot.height, 0, "peer tip is the snapshot base");

    let err = diverged.repair_import_snapshot(&snapshot).expect_err("gap must fail closed");
    assert!(
        matches!(err, DurabilityError::JournalGap { expected: 2, found: 3 }),
        "expected JournalGap(2 -> 3), got {err}"
    );
}

#[test]
fn repair_import_skips_self_checkpoint_records_in_journal() {
    // A journaled self-checkpoint carries the diverged state this
    // repair exists to remove — the replay must skip TAG_CHECKPOINT
    // records and only rebuild from TAG_BLOCK entries on top of the
    // verified peer snapshot.
    let dir = tempfile::tempdir().expect("tempdir");
    let mut diverged = test_executor(100)
        .with_durability(DurabilityConfig::new(dir.path()).with_checkpoint_interval(4096))
        .expect("durability config");
    let counter = Arc::new(CounterModule::new());
    diverged.register_module(counter.clone());
    // Same divergence model as the in-memory test: canonical
    // history through block 1 (identical to the peer's), a
    // committed tail at height 2, then post-execution corruption.
    for h in 0..2u64 {
        diverged.finalize_block(&repair_block(h, vec![make_tx_with_nonce(1, &[9], h)]));
    }
    diverged.finalize_block(&repair_block(
        2,
        vec![make_tx_with_nonce(1, &[1], 2), make_tx_with_nonce(1, &[2], 3)],
    ));
    diverged.wait_exec_idle();
    *primitives::sync::lock_state(&counter.count) = 99;
    // The journal now holds [baseline CHECKPOINT, B0, B1, B2] — the
    // baseline checkpoint records diverged genesis state and must
    // be skipped, not applied.
    let mut peer = test_executor(100);
    peer.register_module(Arc::new(CounterModule::new()));
    for h in 0..2u64 {
        peer.finalize_block(&repair_block(h, vec![make_tx_with_nonce(1, &[9], h)]));
    }
    peer.wait_exec_idle();
    let snapshot = peer.export_snapshot();
    assert_eq!(snapshot.height, 1);

    let covered = diverged.repair_import_snapshot(&snapshot).expect("repair must import");
    assert_eq!(covered, 2, "journal replayed block 2 on the peer base");
    assert_eq!(
        *primitives::sync::lock_state(&counter.count),
        4,
        "self-checkpoint skipped — only peer base + journaled blocks applied"
    );
}

#[test]
fn repair_import_still_verifies_snapshot_before_mutation() {
    // The verified-import gate is unchanged in repair mode: a
    // snapshot whose claimed root does not recompute from its own
    // payloads is refused before any state is touched — the diverged
    // node keeps its (latched) state rather than installing a worse
    // lie.
    let mut diverged = test_executor(100);
    let counter = Arc::new(CounterModule::new());
    diverged.register_module(counter.clone());
    diverged.finalize_block(&repair_block(0, vec![make_tx_with_nonce(1, &[1], 0)]));
    diverged.wait_exec_idle();
    let count_before = *primitives::sync::lock_state(&counter.count);

    let mut peer = test_executor(100);
    peer.register_module(Arc::new(CounterModule::new()));
    peer.finalize_block(&repair_block(0, vec![make_tx_with_nonce(1, &[9], 0)]));
    peer.wait_exec_idle();
    let mut snapshot = peer.export_snapshot();
    snapshot.state_root = Hash([0x77; 32]); // forged root — fails recompute

    let err = diverged.repair_import_snapshot(&snapshot).expect_err("forged root must fail");
    assert!(
        matches!(err, DurabilityError::Import(SnapshotImportError::StateRootMismatch { .. })),
        "expected staged-import root mismatch, got {err}"
    );
    assert_eq!(
        *primitives::sync::lock_state(&counter.count),
        count_before,
        "a refused import must not mutate state"
    );
}

/// The executor's fee floor reads the shared `types::ChainParams`
/// atomics — a store on the handle (what a `chain.min_fee`
/// governance apply performs) moves live enforcement without
/// touching the executor object, proving the enforcement path
/// reads the shared copy rather than a private snapshot.
#[test]
fn shared_chain_params_drive_live_fee_floor() {
    let params = Arc::new(types::ChainParams {
        max_gas: std::sync::atomic::AtomicU64::new(1 << 30),
        max_bytes: std::sync::atomic::AtomicU64::new(1 << 20),
        min_fee: std::sync::atomic::AtomicU64::new(0),
    });
    let mut executor = test_executor(100).with_chain_params(params.clone());
    let counter = Arc::new(CounterModule::new());
    let collector = Arc::new(FeeCollector { charged: Mutex::new(0) });
    executor.register_module(counter.clone());
    executor.register_module(collector.clone());
    executor.set_fee_module(9);

    // With the floor at 0 both txs execute; raising the live floor
    // to 50 (a governance apply's write) must skip the 10-fee tx.
    params.min_fee.store(50, std::sync::atomic::Ordering::Relaxed);
    executor.ingest_tx(make_tx_with_fee_and_sender(1, &[1], 0, 10, 7));
    executor.ingest_tx(make_tx_with_fee_and_sender(1, &[1], 0, 100, 8));
    let budget = types::BlockBudget { max_bytes: 1 << 20, max_gas: 1 << 30 };
    let proposal = executor.prepare_proposal(&budget);
    executor.finalize_block(&FinalizedBlock {
        context: types::BlockContext::default(),
        height: Height::new(0),
        txs: proposal.txs,
        signers: Vec::new(),
    });
    assert_eq!(
        *primitives::sync::lock_state(&counter.count),
        1,
        "only the adequately-paid tx executes under the shared floor"
    );
    assert_eq!(*primitives::sync::lock_state(&collector.charged), 100);
}
