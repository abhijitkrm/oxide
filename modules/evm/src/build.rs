//! revm construction for the EVM module.
//!
//! Split from `lib.rs` around the wiring invariant: `build_evm` /
//! `build_spec_evm` / `build_sim_evm` are the only places a revm
//! instance is assembled — spec-gated handlers, the native-market
//! precompile reader, and the block env all converge here, so
//! "which EVM config runs this code path" is auditable in one
//! file.

use super::{
    Context, EvmModule, MainContext, TxEnv, coinbase_read, deadline, native_journal, precompiles,
    trace,
};

impl EvmModule {
    /// Build a `NativeMarketReader` from the wired exchange and
    /// perps modules. Returns an empty reader if no modules are
    /// wired (all precompile reads return empty/zero).
    pub(crate) fn build_reader(&self) -> precompiles::native::NativeMarketReader {
        let exchange = framework::lock_state(&self.exchange).clone();
        let perps = framework::lock_state(&self.perps).clone();
        precompiles::native::NativeMarketReader::new(exchange, perps)
    }

    /// Build a revm `Evm` with `NativePrecompiles` wired in. This
    /// replaces `build_mainnet_with_inspector` so that EVM contracts
    /// can call Oxide native precompile addresses.
    ///
    /// Generic over the database type to support both the
    /// single-tx path (`CacheDB<EmptyDB>`) and the batch paths
    /// (`CacheDB<SharedCacheDB>`).
    ///
    /// # Panics
    ///
    /// This function does not panic.
    /// Consensus-path EVM builder — strict validation (all checks on).
    #[allow(clippy::type_complexity)]
    pub(crate) fn build_evm<'db, DB>(
        &self,
        db: &'db mut DB,
        coinbase: revm::primitives::Address,
        block_number: u64,
        block_timestamp: u64,
    ) -> revm::context::Evm<
        revm::context::Context<
            revm::context::BlockEnv,
            TxEnv,
            revm::context::CfgEnv,
            &'db mut DB,
            revm::context::Journal<&'db mut DB>,
            (),
        >,
        (native_journal::NativeJournalInspector, trace::CallRecorder),
        revm::handler::instructions::EthInstructions<
            revm::interpreter::interpreter::EthInterpreter,
            revm::context::Context<
                revm::context::BlockEnv,
                TxEnv,
                revm::context::CfgEnv,
                &'db mut DB,
                revm::context::Journal<&'db mut DB>,
                (),
            >,
        >,
        precompiles::NativePrecompiles,
        revm::handler::EthFrame<revm::interpreter::interpreter::EthInterpreter>,
    >
    where
        DB: revm::database_interface::Database,
    {
        self.build_evm_with_mode(db, coinbase, block_number, block_timestamp, false, false)
    }

    /// Speculative EVM builder for the parallel executor: identical
    /// to [`build_evm`](Self::build_evm) but with two speculative-only
    /// guards — read-only native precompiles (a speculative frame can
    /// never write shared native state outside its own `CacheDB`
    /// clone; suppressed mutations surface via
    /// `blocked_native_mutation`)
    /// and a [`CoinbaseReadDetector`](coinbase_read) flagging
    /// `BALANCE(coinbase)` observations so the commit phase can
    /// validate them against the canonical running tip total.
    #[allow(clippy::type_complexity)]
    pub(crate) fn build_spec_evm<'db, DB>(
        &self,
        db: &'db mut DB,
        coinbase: revm::primitives::Address,
        block_number: u64,
        block_timestamp: u64,
    ) -> revm::context::Evm<
        revm::context::Context<
            revm::context::BlockEnv,
            TxEnv,
            revm::context::CfgEnv,
            &'db mut DB,
            revm::context::Journal<&'db mut DB>,
            (),
        >,
        (
            native_journal::NativeJournalInspector,
            (trace::CallRecorder, coinbase_read::CoinbaseReadDetector),
        ),
        revm::handler::instructions::EthInstructions<
            revm::interpreter::interpreter::EthInterpreter,
            revm::context::Context<
                revm::context::BlockEnv,
                TxEnv,
                revm::context::CfgEnv,
                &'db mut DB,
                revm::context::Journal<&'db mut DB>,
                (),
            >,
        >,
        precompiles::NativePrecompiles,
        revm::handler::EthFrame<revm::interpreter::interpreter::EthInterpreter>,
    >
    where
        DB: revm::database_interface::Database,
    {
        let (ctx, instruction, precompiles, journal) =
            self.evm_parts(db, coinbase, block_number, block_timestamp, false, true);
        revm::context::Evm::new_with_inspector(
            ctx,
            (
                native_journal::NativeJournalInspector::new(journal),
                (trace::CallRecorder::new(), coinbase_read::CoinbaseReadDetector::new(coinbase)),
            ),
            instruction,
            precompiles,
        )
    }

    /// Assemble the pieces both EVM builders share: the context
    /// (with the sim flag applied to `CfgEnv`), the instruction set,
    /// the native precompiles wired to the undo journal, and the
    /// journal handle itself (the inspector needs the same `Rc`).
    ///
    /// Splitting assembly this way keeps the consensus-path builder
    /// and the simulation builder identical except for the inspector
    /// — the sim path adds the wall-clock deadline, which must never
    /// exist on a committed path.
    ///
    /// `spec_ro` (speculative read-only) makes mutating native
    /// precompiles revert — used by the parallel executor so a
    /// speculative frame can never write shared native state outside
    /// its own `CacheDB` clone. The suppressed mutation is flagged in
    /// the native journal (`blocked_mutation`) so the tx is known to
    /// need canonical re-execution.
    #[allow(clippy::type_complexity)]
    pub(crate) fn evm_parts<'db, DB>(
        &self,
        db: &'db mut DB,
        coinbase: revm::primitives::Address,
        block_number: u64,
        block_timestamp: u64,
        sim: bool,
        spec_ro: bool,
    ) -> (
        revm::context::Context<
            revm::context::BlockEnv,
            TxEnv,
            revm::context::CfgEnv,
            &'db mut DB,
            revm::context::Journal<&'db mut DB>,
            (),
        >,
        revm::handler::instructions::EthInstructions<
            revm::interpreter::interpreter::EthInterpreter,
            revm::context::Context<
                revm::context::BlockEnv,
                TxEnv,
                revm::context::CfgEnv,
                &'db mut DB,
                revm::context::Journal<&'db mut DB>,
                (),
            >,
        >,
        precompiles::NativePrecompiles,
        std::rc::Rc<std::cell::RefCell<native_journal::NativeJournal>>,
    )
    where
        DB: revm::database_interface::Database,
    {
        let reader = self.build_reader();
        let ctx = Context::mainnet()
            .with_db(db)
            .modify_cfg_chained(|cfg| {
                cfg.set_spec_and_mainnet_gas_params(self.spec);
                if sim {
                    // Read-only call env (`eth_call`/`eth_estimateGas`),
                    // matching geth's `DoCall`/reth's call env:
                    // - nonce: callers rarely set it.
                    // - base fee: callers may omit gasPrice.
                    // - block gas limit: calls may exceed the block
                    //   limit (bounded by our own cap instead).
                    // - priority-fee check: call objects often set
                    //   only `gasPrice`, never a tip cap.
                    // - EIP-3607: calls from accounts *with code* are
                    //   legitimate for eth_call (simulating a contract
                    //   as sender), unlike txs.
                    // Balance and fee checks stay enabled — geth
                    // rejects calls the sender cannot afford
                    // (`gas*price + value`), and so do we.
                    cfg.disable_nonce_check = true;
                    cfg.disable_base_fee = true;
                    cfg.disable_block_gas_limit = true;
                    cfg.disable_priority_fee_check = true;
                    cfg.disable_eip3607 = true;
                }
            })
            .modify_block_chained(|block| {
                block.number = revm::primitives::U256::from(block_number);
                block.beneficiary = coinbase;
                block.timestamp = revm::primitives::U256::from(block_timestamp);
                block.gas_limit = self.block_gas_limit();
                block.basefee = self.current_base_fee();
            });
        let instruction = revm::handler::instructions::EthInstructions::<
            revm::interpreter::interpreter::EthInterpreter,
            _,
        >::new_mainnet_with_spec(self.spec);
        // Frame-scoped undo journal for native mutations (staking
        // delegate/undelegate): the precompile records an undo op per
        // mutation, the inspector replays them on frame revert — the
        // geth `StateDB` journal semantics for non-EVM state.
        let journal =
            std::rc::Rc::new(std::cell::RefCell::new(native_journal::NativeJournal::new()));
        let mut precompiles =
            precompiles::NativePrecompiles::new(self.spec, reader, journal.clone());
        if let Some(staking) = framework::lock_state(&self.staking).clone() {
            precompiles = precompiles.with_staking(staking);
        }
        if sim || spec_ro {
            precompiles = precompiles.read_only();
        }
        (ctx, instruction, precompiles, journal)
    }

    /// Simulation-path EVM builder — same machine as
    /// [`build_evm`](Self::build_evm) plus a
    /// [`deadline::DeadlineInspector`] enforcing the wall-clock
    /// simulation bound. Used only by read-only calls; committed
    /// execution must never carry a wall clock (determinism).
    #[allow(clippy::type_complexity)]
    pub(crate) fn build_sim_evm<'db, DB>(
        &self,
        db: &'db mut DB,
        coinbase: revm::primitives::Address,
        block_number: u64,
        block_timestamp: u64,
        deadline: std::time::Instant,
    ) -> revm::context::Evm<
        revm::context::Context<
            revm::context::BlockEnv,
            TxEnv,
            revm::context::CfgEnv,
            &'db mut DB,
            revm::context::Journal<&'db mut DB>,
            (),
        >,
        (
            (native_journal::NativeJournalInspector, trace::CallRecorder),
            deadline::DeadlineInspector,
        ),
        revm::handler::instructions::EthInstructions<
            revm::interpreter::interpreter::EthInterpreter,
            revm::context::Context<
                revm::context::BlockEnv,
                TxEnv,
                revm::context::CfgEnv,
                &'db mut DB,
                revm::context::Journal<&'db mut DB>,
                (),
            >,
        >,
        precompiles::NativePrecompiles,
        revm::handler::EthFrame<revm::interpreter::interpreter::EthInterpreter>,
    >
    where
        DB: revm::database_interface::Database,
    {
        let (ctx, instruction, precompiles, journal) =
            self.evm_parts(db, coinbase, block_number, block_timestamp, true, false);
        revm::context::Evm::new_with_inspector(
            ctx,
            (
                (native_journal::NativeJournalInspector::new(journal), trace::CallRecorder::new()),
                deadline::DeadlineInspector::new(deadline),
            ),
            instruction,
            precompiles,
        )
    }

    #[allow(clippy::type_complexity)]
    pub(crate) fn build_evm_with_mode<'db, DB>(
        &self,
        db: &'db mut DB,
        coinbase: revm::primitives::Address,
        block_number: u64,
        block_timestamp: u64,
        sim: bool,
        spec_ro: bool,
    ) -> revm::context::Evm<
        revm::context::Context<
            revm::context::BlockEnv,
            TxEnv,
            revm::context::CfgEnv,
            &'db mut DB,
            revm::context::Journal<&'db mut DB>,
            (),
        >,
        (native_journal::NativeJournalInspector, trace::CallRecorder),
        revm::handler::instructions::EthInstructions<
            revm::interpreter::interpreter::EthInterpreter,
            revm::context::Context<
                revm::context::BlockEnv,
                TxEnv,
                revm::context::CfgEnv,
                &'db mut DB,
                revm::context::Journal<&'db mut DB>,
                (),
            >,
        >,
        precompiles::NativePrecompiles,
        revm::handler::EthFrame<revm::interpreter::interpreter::EthInterpreter>,
    >
    where
        DB: revm::database_interface::Database,
    {
        let (ctx, instruction, precompiles, journal) =
            self.evm_parts(db, coinbase, block_number, block_timestamp, sim, spec_ro);
        revm::context::Evm::new_with_inspector(
            ctx,
            (
                native_journal::NativeJournalInspector::new(journal),
                // Call-tree recorder: feeds `debug_trace*` — see
                // trace.rs for why traces are captured at execution
                // time rather than re-executed on demand.
                trace::CallRecorder::new(),
            ),
            instruction,
            precompiles,
        )
    }
}
