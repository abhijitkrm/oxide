//! Oxide blockchain — `storage` crate: the persistence and authentication
//! layer under every state transition (docs/storage-spec.md).
//!
//! ## What this crate is (Phase 0 scope)
//!
//! Three primitives and one seam:
//! - [`journal`]: an append-only log of length-framed, CRC-32-checked
//!   records in size-bounded segment files, with group commit — the
//!   write path a block committer drives once per ~50–100ms batch.
//! - [`mmr`]: a Merkle Mountain Range over leaf hashes — O(1) amortized
//!   appends, one root committing the entire log, O(log n) inclusion
//!   proofs.
//! - [`backend`]: the `StorageBackend` port (plan.md §2.3) plus
//!   `Volatile`, the in-memory reference implementation used by sims
//!   and as the conformance oracle.
//!
//! ## Why this shape (from first principles)
//!
//! State at Oxide's commit cadence cannot afford fsync-per-op or
//! compaction stalls (an LSM's background work is a latency hazard at
//! 50ms blocks), so durability is *replayed*: the journal appends once
//! per block batch (one `fdatasync`), and any node can rebuild state
//! from genesis by replaying segments — the same determinism invariant
//! that keeps validators in agreement. Authentication rides an MMR
//! because its append-only shape matches the log exactly (no re-hashing
//! of cold history, unlike a Merkle-Patricia trie).
//!
//! ## Invariants
//!
//! - The journal **core** (framing, CRC, IO) is std-only forever
//!   (production-rust skill §5); only the merkle layer hashes, via
//!   BLAKE3, whose choice is consensus-critical (spec §3).
//! - Replay never panics on corrupted bytes: torn or bad-CRC tails are
//!   reported as `truncated_at`, everything before them is trustworthy
//!   (spec §2 rule 1).
//! - MMR proofs are self-contained (leaf index, leaf count, path,
//!   peaks) and verify against the root alone — no trusted node needed.

pub mod auth_journal;
pub mod backend;
pub mod journal;
pub mod mmr;

#[cfg(feature = "redb")]
pub mod redb_backend;

#[cfg(feature = "rocksdb")]
pub mod rocksdb_backend;

#[cfg(feature = "mdbx")]
pub mod mdbx_backend;

pub use auth_journal::{
    AuthenticatedJournal, AuthenticatedReplay, JournalBackend, replay_verified,
};
pub use backend::{Caps, Op, Snapshot, SnapshotError, StorageBackend, Volatile};
pub use journal::{JournalConfig, JournalWriter, Location, Replay, ReplayRecord, replay};
pub use mmr::{Mmr, MmrProof, PathStep};

#[cfg(feature = "redb")]
pub use redb_backend::RedbBackend;

#[cfg(feature = "rocksdb")]
pub use rocksdb_backend::RocksDbBackend;

#[cfg(feature = "mdbx")]
pub use mdbx_backend::MdbxBackend;
