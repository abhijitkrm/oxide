//! oxideBFT — the default consensus engine (docs/oxidebft-spec.md).
//!
//! A pipelined 2-chain `HotStuff` with an active pacemaker, BLS12-381
//! quorum certificates, and tail-fork resistance. This crate implements
//! the `ports::ConsensusEngine` trait; the application never sees these
//! types — it sees only the OAI boundary (`types::BlockRecord`,
//! `types::FinalizedBlock`).
//!
//! # Phase 1 staged implementation (oxideBFT spec §8)
//!
//! - **Stage 1** (done): vote/QC/TC types in `types`.
//! - **Stage 2** (done): the pacemaker as a state machine over views.
//! - **Stage 3** (done): single-leader happy path — the engine
//!   proposes, self-votes, forms QCs, and commits via the OAI boundary.
//! - **Stage 4** (done): 2-chain commit rule + multi-validator support.
//! - **Stage 5** (done): BLS aggregation via `blst`.
//! - **Stage 6** (this commit): epoch rotation (two-phase handoff).
//!
//! Each stage ships behind the conformance suite; no stage closes
//! until the suite passes.

pub mod engine;
pub mod pacemaker;
pub mod sequencer;
pub mod validator;
mod verify;
pub mod wal;

pub use engine::{
    ConsensusError, EpochRotationError, OxideBft, PROPOSAL_FUTURE_VIEWS, PROPOSAL_PAST_VIEWS,
    PROPOSAL_VERIFY_BUDGET_PER_SEC, proposer_hash,
};
pub use pacemaker::{Pacemaker, PacemakerEvent, PacemakerState};
pub use sequencer::SequencerEngine;
pub use types::ExecDivergence;
pub use validator::{ValidatorIndex, ValidatorSet};
pub use verify::verify_exec_cert;
pub use wal::{Wal, WalEntry, WalError};
