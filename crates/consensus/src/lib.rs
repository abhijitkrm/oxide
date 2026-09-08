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
//! - **Stage 2** (this commit): the pacemaker as a state machine over
//!   views — timeout → TC formation → view advance. No networking; the
//!   consensus loop (stage 3) drives it.
//! - Stages 3-6: single-leader happy path, view changes, BLS
//!   aggregation, epoch rotation.
//!
//! Each stage ships behind the conformance suite; no stage closes
//! until the suite passes.

pub mod pacemaker;
pub mod validator;

pub use pacemaker::{Pacemaker, PacemakerEvent, PacemakerState};
pub use validator::{ValidatorIndex, ValidatorSet};
