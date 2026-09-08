//! The broadcast (data availability) port.
//!
//! # What this is
//!
//! The seam by which a consensus engine disseminates block *data*
//! (proposal bodies, transaction batches) to the rest of the
//! validator set, separate from the consensus *voting* channel. This
//! separation is the standard HotStuff-family pattern: the consensus
//! hot path orders small headers (hashes + QCs), while the bulk data
//! travels through a broadcast/DA layer that can be optimized
//! independently (erasure coding, chunk pipelining, external DA).
//!
//! # Why a port
//!
//! The default is erasure-coded broadcast with f+1 proof-of-availability
//! votes (plan.md §2.1, §4.7). Small devnets can use `PlainGossip`
//! (just send the whole block to every peer). Post-testnet, an
//! external-DA adapter (Celestia-style) may be wired in. The trait
//! makes the swap a configuration choice, not a code change — and the
//! conformance suite proves the adapter honors the contract.
//!
//! # Phase 0 scope
//!
//! Trait + capability flags only. The first implementation (erasure-
//! coded broadcast) lands in Phase 1 with oxideBFT. A `PlainGossip`
//! dev adapter may land earlier for devnet bring-up.

use types::Proposal;

/// Capability flags a [`BroadcastEngine`] advertises. Callers
/// (config validation, conformance) check these to ensure the adapter
/// supports the deployment's requirements before wiring it in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BroadcastCaps {
    /// `true` if the adapter provides a proof of availability (f+1
    /// votes that the data was retrievable). Erasure-coded broadcast
    /// does; `PlainGossip` does not (it assumes a small, honest
    /// devnet).
    pub proof_of_availability: bool,
    /// `true` if the adapter erasure-codes the data (tolerates f
    /// missing pieces). Erasure-coded broadcast does; `PlainGossip`
    /// does not (it sends the whole block to every peer).
    pub erasure_coded: bool,
    /// Maximum block payload size the adapter supports, in bytes.
    /// Erasure coding has chunk-size limits; `PlainGossip` is bounded
    /// only by the transport's max message size.
    pub max_payload_bytes: u64,
}

/// The broadcast (data availability) port. Implemented by the default
/// erasure-coded broadcast engine and by dev/test adapters
/// (`PlainGossip`).
///
/// v0 is synchronous (matching the OAI v0 traits); Phase 1 revisits
/// the boundary shape with oxideBFT's real I/O loop.
pub trait BroadcastEngine: Send {
    /// Broadcast a proposal's data to the validator set. Returns
    /// `Ok(())` once the data has been disseminated (or, for
    /// proof-of-availability adapters, once the f+1 `PoA` votes have
    /// been collected); `Err` if dissemination failed irrecoverably.
    ///
    /// The proposal is passed by reference — the engine does not
    /// take ownership; the caller (consensus engine) retains it for
    /// its own bookkeeping.
    ///
    /// # Errors
    ///
    /// Returns [`BroadcastError::PayloadTooLarge`] if the proposal
    /// exceeds the adapter's `max_payload_bytes`, or
    /// [`BroadcastError::DisseminationFailed`] on irrecoverable peer
    /// errors / timeouts.
    fn broadcast(&mut self, proposal: &Proposal) -> Result<(), BroadcastError>;

    /// The capabilities this adapter provides. Checked at wiring time
    /// (config validation) and by the conformance suite.
    fn capabilities(&self) -> BroadcastCaps;
}

/// Ways a broadcast can fail. Kept minimal in v0; Phase 1 adds
/// timeout, peer-count, and erasure-reconstruction-failure variants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BroadcastError {
    /// The payload exceeded the adapter's `max_payload_bytes`.
    PayloadTooLarge,
    /// Dissemination failed (peer errors, timeouts). Phase 1 splits
    /// this into per-cause variants; v0 surfaces the single case.
    DisseminationFailed,
}
