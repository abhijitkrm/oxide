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
//! - **Stage 3** (this commit): single-leader happy path — the engine
//!   proposes, self-votes, forms QCs, and commits via the OAI boundary.
//!   1-chain commit rule (safe in the happy path); 2-chain is stage 4.
//! - Stages 4-6: view changes, BLS aggregation, epoch rotation.
//!
//! Each stage ships behind the conformance suite; no stage closes
//! until the suite passes.

pub mod engine;
pub mod pacemaker;
pub mod validator;

pub use engine::OxideBft;
pub use pacemaker::{Pacemaker, PacemakerEvent, PacemakerState};
pub use validator::{ValidatorIndex, ValidatorSet};
