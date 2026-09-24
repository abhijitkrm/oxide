//! One validator of a multi-validator cluster, assembled exactly
//! the way `oxide-devnet` boots it — THE shared startup path for
//! the production devnet binary and the in-memory/TCP harnesses.
//!
//! # What is shared vs. what is a seam
//!
//! Shared (this module): executor + full module graph via
//! [`crate::assemble_executor`], `OxideBft` construction with the
//! configured pacemaker timeouts and block budget, optional WAL
//! recovery, and the committee-membership gate. Divergence here is
//! where the "harness tested a different system" class of bug
//! lives, so there is exactly one path.
//!
//! Seams (the caller injects):
//!
//! - **I/O**: the transport is *not* part of the node — the
//!   consensus pump drives it (`oxide-devnet`'s process loop,
//!   `TcpMultiNodeDevnet`'s threaded pump, `MultiNodeDevnet`'s
//!   deterministic stepper). Each caller builds whatever
//!   `ports::Transport` it needs; nothing in the node itself
//!   assumes TCP.
//! - **Clock**: `spec.clock` feeds [`OxideBft::with_clock`] —
//!   `None` selects `types::system_time_ms` (production), a
//!   deterministic counter is what the in-memory sim injects.
//! - **Storage**: `spec.wal_path` selects the safety-state file;
//!   `None` keeps the WAL in-memory. Executor persistence is
//!   already a `NodeConfig` field (`storage_path`), and
//!   [`import_snapshot_if_present`]/[`export_snapshot`] cover the
//!   data-dir snapshot convention.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use codec::{Decode, Encode};
use executor::Executor;

use crate::{AssembledExecutor, NodeConfig};

/// Everything needed to assemble one validator of a
/// multi-validator cluster.
///
/// The caller resolves the *identity* inputs (index, validator
/// set, secret key) — `oxide-devnet` derives them from
/// `--node`/`--genesis-file`, the harnesses from their
/// deterministic key conventions — while this module owns the
/// *system* assembly, so both consume the same code.
pub struct DevnetNodeSpec {
    /// This node's slot in `validator_set` — the index its secret
    /// key must resolve to on a fresh start.
    pub index: usize,
    /// The committee: genesis-file validators in the binary, the
    /// harness's deterministic set otherwise.
    pub validator_set: consensus::ValidatorSet,
    /// This node's consensus signer — votes/QC contributions and
    /// handshake proofs. A trait object, not the raw key: a
    /// remote-signer deployment keeps the secret outside the node
    /// process entirely. `Arc::new(secret_key)` is the in-process
    /// path every current caller takes.
    pub signer: Arc<dyn crypto::ConsensusSigner>,
    /// The resolved node config — executor graph, genesis, chain
    /// id, block budget, and pacemaker timeouts all propagate from
    /// here (never from engine-compiled defaults).
    pub config: NodeConfig,
    /// Clock seam: the source of block/proposal timestamps.
    /// `None` = `types::system_time_ms` (production wall clock).
    pub clock: Option<Arc<dyn Fn() -> u64 + Send + Sync>>,
    /// Storage seam: the consensus WAL file persisting
    /// safety-critical state (`last_voted_view`, `high_qc`,
    /// `last_committed`, vote locks). `None` falls back to
    /// `config.wal_path` (itself derived from the data dir); both
    /// `None` = no persistence (the in-memory harnesses).
    pub wal_path: Option<PathBuf>,
}

/// A fully assembled multi-validator node, ready for a caller's
/// consensus pump to drive.
pub struct DevnetNode {
    /// The `OxideBft` engine — configured timeouts, block budget,
    /// clock, and (if present) WAL applied.
    pub engine: consensus::OxideBft,
    /// The executor with the full module graph and exec lane.
    pub app: Arc<Executor>,
    /// The EVM module — the chain's native-token ledger.
    pub evm_module: Arc<evm::EvmModule>,
    /// The staking module — committee source for native modules.
    pub staking_module: Arc<staking::StakingModule>,
    /// The exchange module — for settlement/book inspection.
    pub exchange_module: Arc<exchange::ExchangeModule>,
    /// Whether WAL recovery ran. A recovered engine may run a
    /// *rotated* committee, so the membership gate is relaxed to
    /// presence-only after recovery (see [`DevnetStartError`]).
    pub recovered: bool,
    /// Crash-durability recovery report from executor assembly —
    /// `None` when no durability directory is configured, `Some`
    /// otherwise (an empty report means a fresh start). Callers
    /// print it and use it to gate genesis-only work that must not
    /// re-run over recovered state.
    pub recovery: Option<executor::RecoveryReport>,
    /// The consensus WAL path actually attached — the spec's
    /// explicit value or the config-derived `<data_dir>/consensus.wal`
    /// fallback. `None` = WAL persistence disabled.
    pub wal_path: Option<PathBuf>,
}

/// Why [`assemble_devnet_node`] refused to start a node.
///
/// These are startup-fatal conditions the binary maps to
/// `exit(1)` and harnesses propagate — never silently ignored: a
/// validator that cannot produce verifiable votes emits only
/// rejected noise, and a half-open WAL leaves consensus safety
/// state unprotected.
#[derive(Debug)]
pub enum DevnetStartError {
    /// The secret key does not resolve to any committee member
    /// (post-recovery set if a WAL was loaded) — this node is no
    /// longer a validator.
    NotInCommittee {
        /// The epoch whose committee rejected the key.
        epoch: u64,
    },
    /// Fresh start: the key resolved to a different slot than the
    /// requested index — the key file belongs to another validator.
    WrongValidatorSlot {
        /// The `--node`/harness index requested.
        expected: usize,
        /// The slot the key actually resolves to (`None` = none).
        resolved: Option<u16>,
    },
    /// The WAL file could not be opened or recovered.
    Wal {
        /// The `--wal-file` path.
        path: PathBuf,
        /// The underlying WAL error.
        source: consensus::wal::WalError,
    },
}

impl std::fmt::Display for DevnetStartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotInCommittee { epoch } => write!(
                f,
                "BLS key is not in the active validator set (epoch {epoch}) — \
                 this node is no longer a committee member"
            ),
            Self::WrongValidatorSlot { expected, resolved } => write!(
                f,
                "BLS key resolves to validator index {resolved:?}, not {expected} — \
                 the key file does not match this node's identity"
            ),
            Self::Wal { path, source } => {
                write!(f, "WAL {} failed: {source}", path.display())
            }
        }
    }
}

impl std::error::Error for DevnetStartError {}

/// Assemble one validator of a multi-validator cluster through the
/// production path.
///
/// Order matters: the executor is assembled first (module graph +
/// genesis), then the engine is configured (key, timeouts, budget,
/// clock), then the WAL is attached and recovered — recovery may
/// return a *rotated* validator set, so the membership gate runs
/// last against the committee the engine actually runs.
///
/// # Errors
///
/// Returns [`DevnetStartError::Wal`] if the WAL cannot be opened
/// or recovered, [`DevnetStartError::NotInCommittee`] if the secret
/// key is not in the active committee, and
/// [`DevnetStartError::WrongValidatorSlot`] if a fresh start
/// resolves the key to a different slot than `spec.index`.
///
/// # Panics
///
/// Panics if `spec.index` exceeds `u16::MAX` — a validator set
/// that large is a configuration error, not a runtime condition.
pub fn assemble_devnet_node(spec: DevnetNodeSpec) -> Result<DevnetNode, DevnetStartError> {
    let AssembledExecutor { app, evm_module, staking_module, exchange_module, recovery } =
        crate::assemble_executor(&spec.config);
    let app_dyn: Arc<dyn ports::AppInterface> = app.clone();

    let mut engine = consensus::OxideBft::with_index(
        app_dyn,
        spec.validator_set,
        u16::try_from(spec.index).expect("validator index fits in u16"),
    )
    .with_signer(Arc::clone(&spec.signer))
    // Configured timeouts/budget — not engine-compiled defaults —
    // so a `[consensus]` TOML change reaches the harnesses too.
    .with_pacemaker_timeouts(spec.config.base_timeout_ms, spec.config.max_timeout_ms)
    .with_block_budget(spec.config.block_budget);
    if let Some(clock) = spec.clock {
        engine = engine.with_clock(move || clock());
    }

    // WAL persistence + recovery. The explicit spec path wins; the
    // config's derived `<data_dir>/consensus.wal` is the fallback so
    // a durable executor always pairs with a durable engine — without
    // it a restart would re-propose covered heights on top of the
    // recovered tip. Recovery can return a rotated committee, and
    // re-seats our index by matching our BLS key against it.
    let wal_path = spec.wal_path.clone().or_else(|| spec.config.wal_path.clone());
    let recovered = if let Some(ref wal_path) = wal_path {
        if let Some(parent) = wal_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| DevnetStartError::Wal {
                path: wal_path.clone(),
                source: consensus::wal::WalError::Io(e),
            })?;
        }
        let wal = consensus::wal::Wal::open(wal_path)
            .map_err(|source| DevnetStartError::Wal { path: wal_path.clone(), source })?;
        engine = engine.with_wal(wal);
        engine
            .recover_from_wal()
            .map_err(|source| DevnetStartError::Wal { path: wal_path.clone(), source })?;
        true
    } else {
        false
    };

    // Membership gate: our key must resolve to a slot in the
    // committee the engine is actually running. On a fresh start
    // it must be exactly `spec.index` — landing elsewhere means the
    // key file belongs to a different validator, and signing under
    // `spec.index` would emit only invalid votes.
    let our_index = engine.validator_set().index_of_key(&spec.signer.public_key());
    let epoch = engine.epoch().value();
    match (recovered, our_index) {
        (_, None) => return Err(DevnetStartError::NotInCommittee { epoch }),
        (false, Some(resolved)) if resolved != u16::try_from(spec.index).unwrap_or(u16::MAX) => {
            return Err(DevnetStartError::WrongValidatorSlot {
                expected: spec.index,
                resolved: Some(resolved),
            });
        }
        _ => {}
    }

    Ok(DevnetNode {
        engine,
        app,
        evm_module,
        staking_module,
        exchange_module,
        recovered,
        recovery,
        wal_path,
    })
}

/// Import `<data_dir>/snapshot.bin` into `app` if it exists.
///
/// The devnet auto-persistence convention: a restarting node
/// resumes full chain state (not just the WAL) from its data
/// directory. Returns `Some(height)` when a snapshot was imported.
///
/// # Errors
///
/// Returns `Err` if the snapshot file cannot be read, decoded, or
/// imported — a corrupt snapshot must fail loudly rather than
/// silently booting from genesis.
pub fn import_snapshot_if_present(app: &Executor, data_dir: &Path) -> Result<Option<u64>, String> {
    let snap_path = data_dir.join("snapshot.bin");
    if !snap_path.exists() {
        return Ok(None);
    }
    let bytes = std::fs::read(&snap_path)
        .map_err(|e| format!("failed to read snapshot {}: {e}", snap_path.display()))?;
    let mut reader = codec::Reader::new(&bytes);
    let snap = executor::ExecutorSnapshot::decode(&mut reader)
        .map_err(|e| format!("failed to decode snapshot {}: {e}", snap_path.display()))?;
    let height = snap.height;
    app.import_snapshot(&snap)
        .map_err(|e| format!("failed to import snapshot {}: {e}", snap_path.display()))?;
    Ok(Some(height))
}

/// Export `app`'s current state to `<data_dir>/snapshot.bin`,
/// creating the directory if needed. The counterpart to
/// [`import_snapshot_if_present`] — called on shutdown so a
/// restart resumes the full chain state.
///
/// When the executor has durability configured (`--data-dir` →
/// `durability_dir`), this is a full [`Executor::durable_checkpoint`]:
/// the snapshot is written atomically and the block journal's
/// covered segments are pruned. Otherwise the snapshot is still
/// written atomically — write to `.tmp`, fsync, rename, fsync the
/// directory — so a crash mid-write never leaves a torn file that a
/// restart would fail to decode.
///
/// # Errors
///
/// Returns `Err` if the directory cannot be created or the
/// snapshot cannot be written.
pub fn export_snapshot(app: &Executor, data_dir: &Path) -> Result<u64, String> {
    std::fs::create_dir_all(data_dir)
        .map_err(|e| format!("failed to create data dir {}: {e}", data_dir.display()))?;
    if let Some(height) =
        app.durable_checkpoint().map_err(|e| format!("durable checkpoint failed: {e}"))?
    {
        return Ok(height);
    }
    // No durability configured — write the snapshot atomically by
    // hand (the durable path above writes the same file). Skip it
    // entirely when nothing has committed: a height-0 snapshot.bin
    // cannot distinguish "genesis, nothing executed" from "block 0
    // executed" on re-import, and an empty node has nothing to
    // persist anyway.
    if app.committed_height().is_none() {
        return Ok(0);
    }
    let snap = app.export_snapshot();
    let height = snap.height;
    let mut buf = Vec::new();
    snap.encode(&mut buf);
    let snap_path = data_dir.join("snapshot.bin");
    executor::durability::atomic_write(&snap_path, &buf)
        .map_err(|e| format!("failed to write snapshot {}: {e}", snap_path.display()))?;
    Ok(height)
}

/// Recover a restarting node's state from `data_dir`: import the
/// newest `snapshot.bin` checkpoint and replay every journaled block
/// above it. Returns `Ok(None)` when the executor has no durability
/// configured — callers then fall back to
/// [`import_snapshot_if_present`], the pre-journal boot path.
///
/// # Errors
///
/// Returns `Err` when the journal cannot be read, a record is
/// undecodable, heights are non-contiguous, or a checkpoint fails
/// verification — recovery that cannot produce a correct state must
/// stop the boot, not guess.
pub fn recover_durable_state(app: &Executor) -> Result<Option<executor::RecoveryReport>, String> {
    app.recover_durable_state().map_err(|e| format!("durable state recovery failed: {e}"))
}
