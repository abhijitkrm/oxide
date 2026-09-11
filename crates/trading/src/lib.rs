//! HFT-grade matching engine for the Oxide blockchain (plan.md §9.1).
//!
//! ## What this crate is
//!
//! A central-limit-order-book engine built for CME/Nasdaq-class
//! latency in Rust: strict price-time priority, O(1) best-price
//! discovery, and zero heap allocation in the match loop. It is a
//! pure library — no chain state, no modules, no I/O — so it can be
//! benchmarked standalone against the Phase 3 gates (plan.md §13)
//! before it is ever wired into a block.
//!
//! ## Architecture (one paragraph, top to bottom)
//!
//! Orders rest in a slab [`OrderPool`] (one 64-byte cache line per
//! order, `u32` intrusive FIFO links). Price levels are entries in a
//! [`DenseBook`] tick ladder — a flat `Vec` indexed by tick offset —
//! with two hierarchical [`Bitboard`]s marking active bid/ask levels
//! so best-price lookup is a couple of `countl_zero`/`countr_zero`
//! instructions. Cancel locates an order's slot through a
//! preallocated open-addressed [`IdMap`]. The
//! [`MatchingEngine`] orchestrates: validate → (optional FOK
//! pre-scan) → sweep the opposite side best-first, filling FIFO
//! makers → rest or cancel the remainder. All arithmetic is the
//! deterministic fixed-point [`primitives`] vocabulary
//! (`Price` scale-8, `Qty` scale-6) — floats appear nowhere.
//!
//! ## Invariants
//!
//! - **Determinism:** identical operation sequences produce
//!   byte-identical fills and book state on every validator (the
//!   property-test oracle pins this).
//! - **Never crossed:** `best_bid < best_ask` holds after every
//!   operation — marketable volume is matched on submission.
//! - **No allocation in the match loop:** taker orders live on the
//!   stack; only resting remainders take a (recycled) pool slot;
//!   fill events land in a caller-owned buffer.
//! - **Conservation:** level totals always equal the sum of their
//!   linked orders' remaining quantities.
//!
//! ## Phase 3 acceptance gates (plan.md §13)
//!
//! Engine-only ≥5M ops/s single-core; mixed workload ≥1M ops/s/core;
//! insert/cancel p50 < 200ns; match-op p50 < 300ns — all enforced by
//! `benches/matching.rs` (criterion). Oracle equivalence and
//! no-negative-invariant properties live in `tests/properties.rs`
//! (proptest).

#![warn(missing_docs)]

pub mod bitboard;
pub mod book;
pub mod engine;
pub mod error;
pub mod idmap;
pub mod order;
pub mod pool;

pub use book::{BookBackend, DenseBook, MarketConfig, PriceLevel};
pub use engine::{CanceledOrder, FillEvent, MatchingEngine, OrderOutcome, RestingEntry};
pub use error::{RejectReason, TradingError};
pub use idmap::IdMap;
pub use order::{NewOrder, OrderId, OrderType, Side, StpMode, TimeInForce};
pub use pool::{NIL, OrderNode, OrderPool, fresh_node};
