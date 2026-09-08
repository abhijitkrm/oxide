//! Oxide runtime: a safe, std-only deterministic single-threaded
//! executor for simulations and tests.
//!
//! This is the reproducibility backbone of Oxide's five-layer test
//! pyramid (testing-standards skill §4). The production runtime — a
//! tokio-backed, multi-threaded, I/O-aware executor — arrives in Phase
//! 1 as a *sibling* implementation, not a rewrite of this one: both
//! expose the same [`scheduler::Handle`] spawn shape so simulation
//! code and production code share task bodies.
//!
//! # Why not just use `tokio`?
//!
//! `tokio`'s scheduling order is deliberately unspecified (work-stealing
//! across threads, timer-wheel ordering, I/O readiness). That is
//! correct for production but fatal for *deterministic* simulation,
//! where the same input must yield the same output every run so a flaky
//! failure can be bisected. This crate pins the order: FIFO ready
//! queue, FIFO mailboxes, no timers, no I/O, no threads.
//!
//! # What's here
//!
//! - [`scheduler::Runtime`] / [`scheduler::Handle`] — the executor.
//! - [`mailbox::Mailbox`] — the simulation network edge.
//!
//! Both are `unsafe`-free (the workspace denies `unsafe_code`).

pub mod mailbox;
pub mod scheduler;

pub use mailbox::{Mailbox, Recv};
pub use scheduler::{Handle, Runtime};
