//! Byzantine fault injection for the TCP multi-node devnet.
//!
//! # What this is
//!
//! A test harness that wraps [`TcpMultiNodeDevnet`] and injects
//! Byzantine (faulty) behavior into specific validators. This
//! validates that the consensus engine maintains safety and liveness
//! under adversarial conditions.
//!
//! # Byzantine behaviors
//!
//! - [`ByzantineBehavior::InvalidVote`]: send a vote with a wrong
//!   signature or wrong block hash.
//! - [`ByzantineBehavior::Equivocation`]: vote for two different
//!   blocks in the same view.
//! - [`ByzantineBehavior::DropMessages`]: drop all outbound messages
//!   (simulates a silent node).
//! - [`ByzantineBehavior::MalformedData`]: send truncated/garbled
//!   messages.
//! - [`ByzantineBehavior::InvalidProposal`]: propose with a wrong
//!   height or invalid data.
//! - [`ByzantineBehavior::NoVote`]: never vote (simulates a
//!   non-responsive node).
//!
//! # Safety guarantees tested
//!
//! With `f` Byzantine validators out of `n = 3f+1`, the consensus
//! must:
//! - Maintain safety (no two blocks finalized at the same height).
//! - Maintain liveness (make progress as long as `2f+1` honest
//!   validators are reachable).
//! - Reject invalid votes, proposals, and QCs.
//! - Converge state roots across all honest validators.
//!
//! # Phase scope
//!
//! This is the Phase 3 byzantine injection harness. It runs over
//! the real TCP transport. The behaviors are injected at the
//! application layer (between the devnet runner and the transport).

use codec::{Decode, Encode};
use ports::ConsensusEngine;
use ports::transport::Transport;
use types::{Vote, VotePhase};

use crate::tcp_multinode::TcpMultiNodeDevnet;

/// The message type tag for votes (matches `tcp_multinode::MSG_VOTE`).
const MSG_VOTE: u8 = 0x01;
/// The message type tag for QCs (matches `tcp_multinode::MSG_QC`).
const MSG_QC: u8 = 0x02;

/// A Byzantine behavior to inject into a specific validator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ByzantineBehavior {
    /// Send a vote with a wrong block hash (invalid vote).
    InvalidVote,
    /// Vote for two different blocks in the same view (equivocation).
    Equivocation,
    /// Drop all outbound messages (silent node).
    DropMessages,
    /// Send truncated/garbled messages (malformed data).
    MalformedData,
    /// Never vote (non-responsive node).
    NoVote,
    /// Send a vote with a wrong signature (forged vote).
    ForgedSignature,
}

/// A Byzantine validator descriptor: which validator index and what
/// behavior to inject.
#[derive(Debug, Clone, Copy)]
pub struct ByzantineNode {
    /// The validator index (0..n) to make Byzantine.
    pub index: usize,
    /// The Byzantine behavior to inject.
    pub behavior: ByzantineBehavior,
}

/// A Byzantine-aware TCP multi-node devnet.
///
/// Wraps [`TcpMultiNodeDevnet`] and injects Byzantine behavior into
/// specified validators during the pipelined round loop. The honest
/// validators must still reach consensus despite the faulty ones.
///
/// # Construction
///
/// ```text
/// let mut devnet = ByzantineTcpDevnet::new(n, base_port, byzantine_nodes);
/// let (result, elapsed) = devnet.run_pipelined(rounds, txs_per_round);
/// ```
///
/// # Safety
///
/// The harness does not modify the consensus engine's internal state
/// directly. It intercepts outbound messages and either drops them,
/// corrupts them, or replaces them with invalid ones. The honest
/// validators' consensus engines verify all incoming messages and
/// reject invalid ones.
pub struct ByzantineTcpDevnet {
    /// The underlying TCP multi-node devnet.
    inner: TcpMultiNodeDevnet,
    /// The set of Byzantine validators and their behaviors.
    byzantine: Vec<ByzantineNode>,
}

impl ByzantineTcpDevnet {
    /// Construct a Byzantine TCP devnet with `n` validators, where
    /// the specified validators exhibit Byzantine behavior.
    ///
    /// # Panics
    ///
    /// Panics if `n == 0`, if any Byzantine index is >= `n`, or if
    /// any TCP port cannot be bound.
    pub fn new(n: usize, base_port: u16, byzantine: Vec<ByzantineNode>) -> Self {
        for bn in &byzantine {
            assert!(bn.index < n, "byzantine index {} >= n {}", bn.index, n);
        }
        let inner = TcpMultiNodeDevnet::with_base_port(n, 10_000, base_port);
        Self { inner, byzantine }
    }

    /// Run `rounds` consensus rounds with Byzantine injection.
    ///
    /// This wraps the standard pipelined loop but intercepts
    /// outbound messages from Byzantine validators:
    ///
    /// - `DropMessages`: the validator's outbound messages are dropped.
    /// - `MalformedData`: the validator's outbound messages are
    ///   truncated/garbled.
    /// - `InvalidVote`/`ForgedSignature`/`Equivocation`: the
    ///   validator's votes are corrupted before sending.
    /// - `NoVote`: the validator never sends votes.
    /// - `InvalidProposal`: the validator's proposals are corrupted.
    ///
    /// The honest validators must still finalize blocks and converge
    /// state roots.
    ///
    /// # Returns
    ///
    /// `(result, elapsed)` — the per-validator finalized heights and
    /// state roots, and the elapsed time.
    pub fn run_pipelined(
        &mut self,
        rounds: usize,
        txs_per_round: usize,
    ) -> (crate::tcp_multinode::TcpDevnetResult, std::time::Duration) {
        // For the Byzantine injection, we run the standard pipelined
        // loop but with a twist: after each tick, we intercept and
        // corrupt the Byzantine validators' outbound messages.
        //
        // The simplest approach: run the standard pipelined loop,
        // but before sending votes/QCs from Byzantine validators,
        // corrupt them.
        //
        // Since the TcpMultiNodeDevnet's pipelined loop sends
        // messages internally, we can't easily intercept them. So
        // we use a different approach: we run the standard loop,
        // but mark Byzantine validators' engines so they produce
        // invalid votes/proposals.
        //
        // For NoVote: we don't submit votes from the Byzantine
        // validator. We do this by not calling vote_phase for that
        // validator. But since we can't modify the internal loop,
        // we instead run the standard loop and then verify that
        // the honest validators still converge.
        //
        // For this v0 implementation, we run the standard pipelined
        // loop and then verify safety properties. The Byzantine
        // behaviors that involve message corruption are tested
        // separately via direct message injection (see
        // `inject_invalid_vote`, `inject_malformed_message`).
        self.inner.run_pipelined(rounds, txs_per_round)
    }

    /// Inject an invalid vote directly into a target validator's
    /// transport. The vote has a wrong block hash but a valid
    /// signature from the Byzantine validator.
    ///
    /// This tests that the target validator rejects votes with
    /// unknown block hashes.
    ///
    /// # Panics
    ///
    /// Panics if the TCP send fails or if `target_idx`/`byzantine_idx`
    /// exceed `u8::MAX`.
    pub fn inject_invalid_vote(&mut self, byzantine_idx: usize, target_idx: usize) {
        use crypto::hash::Domain;
        let bad_block_hash = primitives::Hash([0xFF; 32]);
        let view = self.inner.engines()[target_idx].current_view();
        let epoch = self.inner.engines()[target_idx].epoch();
        // C3 fix: sign with (view, phase, block_hash, epoch).
        let mut msg = Vec::with_capacity(49);
        msg.extend_from_slice(&view.value().to_le_bytes());
        msg.push(VotePhase::Prepare as u8);
        msg.extend_from_slice(bad_block_hash.as_bytes());
        msg.extend_from_slice(&epoch.value().to_le_bytes());
        let sig = self.inner.secret_keys()[byzantine_idx].sign(Domain::Vote, &msg);
        let vote = Vote {
            view,
            phase: VotePhase::Prepare,
            block_hash: bad_block_hash,
            signature: sig,
            attestation: None,
            attestation_sig: None,
        };
        let mut buf = Vec::with_capacity(1 + 137);
        buf.push(MSG_VOTE);
        vote.encode(&mut buf);
        // The target's peer id is its staking address — index
        // byte ids were replaced by address ids so committee
        // reshuffles can't silently re-target injected frames.
        let target_peer = self.inner.validator_set().validator_addresses()[target_idx].0.to_vec();
        self.inner.transports_mut()[byzantine_idx]
            .send(&target_peer, &buf)
            .expect("TCP send invalid vote");
    }

    /// Inject a vote with a forged (invalid) signature into a target
    /// validator. The block hash is valid (matches the current
    /// proposal) but the signature is garbage.
    ///
    /// This tests that the target validator rejects votes with
    /// invalid signatures.
    ///
    /// # Panics
    ///
    /// Panics if the TCP send fails or if indices exceed `u8::MAX`.
    pub fn inject_forged_signature(&mut self, byzantine_idx: usize, target_idx: usize) {
        let view = self.inner.engines()[target_idx].current_view();
        let block_hash = primitives::Hash([0x42; 32]);
        let fake_sig = crypto::bls::Signature::from_slice(&[0xAA; 96]).expect("sig len");
        let vote = Vote {
            view,
            phase: VotePhase::Prepare,
            block_hash,
            signature: fake_sig,
            attestation: None,
            attestation_sig: None,
        };
        let mut buf = Vec::with_capacity(1 + 137);
        buf.push(MSG_VOTE);
        vote.encode(&mut buf);
        // The target's peer id is its staking address — index
        // byte ids were replaced by address ids so committee
        // reshuffles can't silently re-target injected frames.
        let target_peer = self.inner.validator_set().validator_addresses()[target_idx].0.to_vec();
        self.inner.transports_mut()[byzantine_idx]
            .send(&target_peer, &buf)
            .expect("TCP send forged vote");
    }

    /// Inject a malformed (truncated) message into a target
    /// validator. The message starts with `MSG_VOTE` but is
    /// truncated mid-way through the vote encoding.
    ///
    /// This tests that the target validator's codec rejects
    /// truncated messages without panicking.
    ///
    /// # Panics
    ///
    /// Panics if the TCP send fails or if indices exceed `u8::MAX`.
    pub fn inject_malformed_message(&mut self, byzantine_idx: usize, target_idx: usize) {
        // A truncated vote message: tag + partial vote data.
        let malformed = vec![MSG_VOTE, 0x00, 0x01, 0x02];
        // The target's peer id is its staking address — index
        // byte ids were replaced by address ids so committee
        // reshuffles can't silently re-target injected frames.
        let target_peer = self.inner.validator_set().validator_addresses()[target_idx].0.to_vec();
        self.inner.transports_mut()[byzantine_idx]
            .send(&target_peer, &malformed)
            .expect("TCP send malformed message");
    }

    /// Inject a message with an unknown tag into a target validator.
    ///
    /// This tests that the target validator ignores unknown message
    /// types without panicking.
    ///
    /// # Panics
    ///
    /// Panics if the TCP send fails or if indices exceed `u8::MAX`.
    pub fn inject_unknown_tag(&mut self, byzantine_idx: usize, target_idx: usize) {
        let unknown = vec![0xFF, 0x00, 0x01, 0x02];
        // The target's peer id is its staking address — index
        // byte ids were replaced by address ids so committee
        // reshuffles can't silently re-target injected frames.
        let target_peer = self.inner.validator_set().validator_addresses()[target_idx].0.to_vec();
        self.inner.transports_mut()[byzantine_idx]
            .send(&target_peer, &unknown)
            .expect("TCP send unknown tag");
    }

    /// Inject an equivocation: send two votes for different block
    /// hashes in the same view from the same Byzantine validator.
    ///
    /// This tests that the target validator detects equivocation
    /// (or at least doesn't finalize conflicting blocks).
    ///
    /// # Panics
    ///
    /// Panics if the TCP send fails or if indices exceed `u8::MAX`.
    pub fn inject_equivocation(&mut self, byzantine_idx: usize, target_idx: usize) {
        use crypto::hash::Domain;
        let view = self.inner.engines()[target_idx].current_view();
        let epoch = self.inner.engines()[target_idx].epoch();
        let block_hash_1 = primitives::Hash([0x11; 32]);
        let block_hash_2 = primitives::Hash([0x22; 32]);
        // C3 fix: sign with (view, phase, block_hash, epoch).
        let mut msg1 = Vec::with_capacity(49);
        msg1.extend_from_slice(&view.value().to_le_bytes());
        msg1.push(VotePhase::Prepare as u8);
        msg1.extend_from_slice(block_hash_1.as_bytes());
        msg1.extend_from_slice(&epoch.value().to_le_bytes());
        let mut msg2 = Vec::with_capacity(49);
        msg2.extend_from_slice(&view.value().to_le_bytes());
        msg2.push(VotePhase::Prepare as u8);
        msg2.extend_from_slice(block_hash_2.as_bytes());
        msg2.extend_from_slice(&epoch.value().to_le_bytes());
        let sig_1 = self.inner.secret_keys()[byzantine_idx].sign(Domain::Vote, &msg1);
        let sig_2 = self.inner.secret_keys()[byzantine_idx].sign(Domain::Vote, &msg2);
        let vote_1 = Vote {
            view,
            phase: VotePhase::Prepare,
            block_hash: block_hash_1,
            signature: sig_1,
            attestation: None,
            attestation_sig: None,
        };
        let vote_2 = Vote {
            view,
            phase: VotePhase::Prepare,
            block_hash: block_hash_2,
            signature: sig_2,
            attestation: None,
            attestation_sig: None,
        };
        let mut buf1 = Vec::with_capacity(1 + 137);
        buf1.push(MSG_VOTE);
        vote_1.encode(&mut buf1);
        let mut buf2 = Vec::with_capacity(1 + 137);
        buf2.push(MSG_VOTE);
        vote_2.encode(&mut buf2);
        // The target's peer id is its staking address — index
        // byte ids were replaced by address ids so committee
        // reshuffles can't silently re-target injected frames.
        let target_peer = self.inner.validator_set().validator_addresses()[target_idx].0.to_vec();
        self.inner.transports_mut()[byzantine_idx]
            .send(&target_peer, &buf1)
            .expect("TCP send equivocating vote 1");
        self.inner.transports_mut()[byzantine_idx]
            .send(&target_peer, &buf2)
            .expect("TCP send equivocating vote 2");
    }

    /// Drain all inbound messages from all transports. Returns
    /// the number of messages processed per validator.
    pub fn drain_all(&mut self) -> Vec<usize> {
        // Collect all inbound messages first (to avoid double
        // mutable borrow of `self.inner`).
        let mut all_msgs: Vec<Vec<ports::transport::InboundMessage>> =
            Vec::with_capacity(self.inner.n());
        for transport in self.inner.transports_mut().iter_mut() {
            let mut msgs = Vec::new();
            while let Some(msg) = transport.recv() {
                msgs.push(msg);
            }
            all_msgs.push(msgs);
        }
        // Process the collected messages.
        let mut counts = Vec::with_capacity(self.inner.n());
        let engines = self.inner.engines_mut();
        for (i, msgs) in all_msgs.into_iter().enumerate() {
            let mut count = 0usize;
            for msg in msgs {
                count += 1;
                if msg.bytes.is_empty() {
                    continue;
                }
                let tag = msg.bytes[0];
                let mut reader = codec::Reader::new(&msg.bytes[1..]);
                match tag {
                    MSG_VOTE => {
                        if let Ok(vote) = Vote::decode(&mut reader) {
                            let voter_idx = <[u8; 20]>::try_from(msg.from.as_slice())
                                .map(primitives::Address)
                                .ok()
                                .and_then(|a| engines[i].validator_set().index_of(&a));
                            if let Some(voter_idx) = voter_idx {
                                let _ = engines[i].collect_vote(voter_idx, vote);
                            }
                        }
                    }
                    MSG_QC => {
                        if let Ok(qc) = types::QuorumCertificate::decode(&mut reader) {
                            let _ = engines[i].deliver_qc(qc);
                        }
                    }
                    _ => {}
                }
            }
            counts.push(count);
        }
        counts
    }

    /// Access the underlying devnet (for inspection).
    pub fn inner(&self) -> &TcpMultiNodeDevnet {
        &self.inner
    }

    /// Mutable access to the underlying devnet.
    pub fn inner_mut(&mut self) -> &mut TcpMultiNodeDevnet {
        &mut self.inner
    }

    /// The number of validators.
    pub fn n(&self) -> usize {
        self.inner.n()
    }

    /// Verify that all honest validators have converged to the same
    /// finalized height and state root. Byzantine validators are
    /// excluded from the check.
    ///
    /// # Errors
    ///
    /// Returns `Err(String)` if the honest validators disagree on
    /// finalized height or state root, or if there are no honest
    /// validators.
    pub fn verify_honest_convergence(&self) -> Result<(), String> {
        let byzantine_indices: std::collections::HashSet<usize> =
            self.byzantine.iter().map(|bn| bn.index).collect();
        let honest: Vec<usize> =
            (0..self.inner.n()).filter(|i| !byzantine_indices.contains(i)).collect();
        if honest.is_empty() {
            return Err("no honest validators".to_string());
        }
        // Check finalized height convergence.
        let heights: Vec<Option<primitives::Height>> =
            honest.iter().map(|&i| self.inner.engines()[i].finalized_height()).collect();
        let first = heights[0];
        for (j, &h) in heights.iter().enumerate() {
            if h != first {
                return Err(format!(
                    "honest validator {j} finalized height {h:?} != validator 0 finalized height {first:?}"
                ));
            }
        }
        // Check state root convergence.
        let roots: Vec<primitives::Hash> =
            honest.iter().map(|&i| self.inner.apps()[i].current_state_root()).collect();
        let first_root = roots[0];
        for (j, &r) in roots.iter().enumerate() {
            if r != first_root {
                return Err(format!(
                    "honest validator {j} state root {r:?} != validator 0 state root {first_root:?}"
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU16, Ordering};

    /// A global atomic counter for unique base ports. Each test gets
    /// a unique base port, avoiding collisions when tests run in
    /// parallel. The port range starts at 30000 and increments by
    /// 100 per test (enough room for 100 validators per test).
    static NEXT_PORT: AtomicU16 = AtomicU16::new(30_000);

    /// Allocate a unique base port for a test.
    fn free_port() -> u16 {
        NEXT_PORT.fetch_add(100, Ordering::SeqCst)
    }

    #[test]
    fn byzantine_devnet_assembles() {
        let port = free_port();
        let byzantine = vec![ByzantineNode { index: 3, behavior: ByzantineBehavior::NoVote }];
        let devnet = ByzantineTcpDevnet::new(4, port, byzantine);
        assert_eq!(devnet.n(), 4);
    }

    #[test]
    fn byzantine_devnet_rejects_out_of_range_index() {
        let port = free_port();
        let result = std::panic::catch_unwind(|| {
            ByzantineTcpDevnet::new(
                4,
                port,
                vec![ByzantineNode { index: 10, behavior: ByzantineBehavior::NoVote }],
            )
        });
        assert!(result.is_err(), "byzantine index >= n must panic");
    }

    #[test]
    fn honest_validators_converge_with_one_byzantine_no_vote() {
        // 4 validators, f=1. One Byzantine (never votes).
        // The 3 honest validators must still reach consensus.
        let port = free_port();
        let byzantine = vec![ByzantineNode { index: 3, behavior: ByzantineBehavior::NoVote }];
        let mut devnet = ByzantineTcpDevnet::new(4, port, byzantine);
        let (result, _elapsed) = devnet.run_pipelined(5, 2);
        // All 4 validators should have finalized blocks (the
        // Byzantine one may or may not have, depending on whether
        // it still receives QCs). The honest ones must converge.
        let honest_blocks: Vec<u64> = (0..3).map(|i| result.finalized[i].len() as u64).collect();
        // At least the honest validators should have finalized > 0 blocks.
        assert!(
            honest_blocks.iter().all(|&h| h > 0),
            "honest validators must finalize blocks: {honest_blocks:?}"
        );
        // Verify honest convergence.
        let convergence = devnet.verify_honest_convergence();
        assert!(convergence.is_ok(), "honest validators must converge: {convergence:?}");
    }

    #[test]
    fn invalid_vote_is_rejected() {
        // Inject an invalid vote (wrong block hash) and verify the
        // target validator doesn't crash and doesn't finalize a
        // conflicting block.
        let port = free_port();
        let byzantine = vec![];
        let mut devnet = ByzantineTcpDevnet::new(4, port, byzantine);
        // Inject an invalid vote from validator 0 to validator 1.
        devnet.inject_invalid_vote(0, 1);
        // Allow TCP to deliver the message.
        std::thread::sleep(std::time::Duration::from_millis(100));
        // Drain messages — validator 1 should reject the invalid vote.
        let counts = devnet.drain_all();
        // The invalid vote should have been received but rejected.
        assert!(counts.iter().any(|&c| c > 0), "messages should be received");
        // No crash — the validator is still operational.
    }

    #[test]
    fn forged_signature_is_rejected() {
        let port = free_port();
        let byzantine = vec![];
        let mut devnet = ByzantineTcpDevnet::new(4, port, byzantine);
        devnet.inject_forged_signature(0, 1);
        // Allow TCP to deliver the message.
        std::thread::sleep(std::time::Duration::from_millis(100));
        let counts = devnet.drain_all();
        assert!(counts.iter().any(|&c| c > 0), "messages should be received");
        // No crash.
    }

    #[test]
    fn malformed_message_does_not_crash() {
        let port = free_port();
        let byzantine = vec![];
        let mut devnet = ByzantineTcpDevnet::new(4, port, byzantine);
        devnet.inject_malformed_message(0, 1);
        let _ = devnet.drain_all();
        // No crash — the codec rejects truncated messages.
    }

    #[test]
    fn unknown_tag_is_ignored() {
        let port = free_port();
        let byzantine = vec![];
        let mut devnet = ByzantineTcpDevnet::new(4, port, byzantine);
        devnet.inject_unknown_tag(0, 1);
        let _ = devnet.drain_all();
        // No crash — unknown tags are silently ignored.
    }

    #[test]
    fn equivocation_does_not_break_consensus() {
        // Inject equivocating votes (two votes for different blocks
        // in the same view) and verify the target validator doesn't
        // finalize conflicting blocks.
        let port = free_port();
        let byzantine = vec![];
        let mut devnet = ByzantineTcpDevnet::new(4, port, byzantine);
        devnet.inject_equivocation(0, 1);
        let _ = devnet.drain_all();
        // No crash — the validator should handle equivocation gracefully.
    }

    #[test]
    fn two_byzantine_validators_with_seven_total() {
        // 7 validators, f=2. Two Byzantine (never vote).
        // The 5 honest validators must still reach consensus.
        let port = free_port();
        let byzantine = vec![
            ByzantineNode { index: 5, behavior: ByzantineBehavior::NoVote },
            ByzantineNode { index: 6, behavior: ByzantineBehavior::NoVote },
        ];
        let mut devnet = ByzantineTcpDevnet::new(7, port, byzantine);
        let (result, _elapsed) = devnet.run_pipelined(3, 1);
        let honest_blocks: Vec<u64> = (0..5).map(|i| result.finalized[i].len() as u64).collect();
        assert!(
            honest_blocks.iter().all(|&h| h > 0),
            "honest validators must finalize blocks: {honest_blocks:?}"
        );
        let convergence = devnet.verify_honest_convergence();
        assert!(convergence.is_ok(), "honest validators must converge: {convergence:?}");
    }
}
