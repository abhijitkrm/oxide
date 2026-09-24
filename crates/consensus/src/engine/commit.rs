//! Two-chain commit walk for oxideBFT.
//!
//! Split from `engine.rs` around the finality invariant:
//! [`OxideBft::commit_walk`] walks the certified ancestor chain
//! under a QC'd tip and [`OxideBft::commit_block`] finalizes the
//! contiguous uncommitted prefix oldest-first — a skipped link
//! must never finalize (the `InvNoGap` counterexample TLC
//! produced). A commit only walks blocks whose stored parent IS
//! their certified block (`prev == justify`, enforced at vote
//! time), and an `Awaiting` body defers the whole commit — a
//! dispersed body still propagating must never be finalized over.

use super::{
    Address, BlockBody, BlockHeader, FinalizedBlock, Hash, MAX_RETAINED_FINALIZED, OxideBft,
};

impl OxideBft {
    /// Walk the certified ancestor chain under a QC'd tip and commit
    /// the contiguous uncommitted prefix, oldest-first.
    ///
    /// A block joins the collected chain only while its stored body
    /// is `Complete`: an `Awaiting` ancestor (dispersed body still
    /// propagating as shards) breaks the walk exactly like a missing
    /// block — the contiguity guard below then defers the whole
    /// commit rather than finalizing over an unexecutable body. The
    /// walk re-runs when `supply_body` completes the body or when a
    /// later QC arrives.
    ///
    /// The tip itself is never committed here — it commits only when
    /// a QC for its *child* arrives — so the tip's own body state is
    /// irrelevant to this walk.
    pub(crate) fn commit_walk(&mut self, header: &BlockHeader) {
        // Collect the uncommitted ancestor chain, newest→oldest:
        // (block hash, bitmap of the QC certifying it). The
        // certifying QC for a block X is the embedded `high_qc`
        // of X's child — for the tip that is `header.high_qc`.
        // The walk stops at genesis (prev ZERO / no stored
        // parent), at a committed block (evicted from `blocks`
        // by `commit_block`'s retain — a missing ancestor is
        // always already finalized, since vote-time storage is
        // prefix-closed: a block can only be stored after its
        // parent was), at an `Awaiting` body (dispersed body not
        // yet reconstructed — never commit unexecutable state),
        // or when the embedded-QC chain ends.
        // The walk only applies when the stored block's parent IS
        // its certified block — `prev == justify`, enforced at
        // vote time. A divergent stored block (impossible via the
        // vote path; only a future import seam could create one)
        // would otherwise commit an *uncertified* parent: the
        // embedded QC certifies `justify`, not `prev`.
        //
        // Each collected entry carries the committing pair it would
        // close: `(cursor hash, certifying bitmap, cursor height,
        // cursor view, certifier view)` — where the certifier is the
        // stored child carrying the cursor's QC (`header` for the
        // first link, the previous cursor thereafter).
        let mut chain: Vec<(Hash, Vec<u8>, u64, u64, u64)> = Vec::new();
        if header.high_qc.as_ref().is_some_and(|qc| qc.block_hash == header.prev_block) {
            let mut cursor_hash = header.prev_block;
            let mut certifying = header.high_qc.clone();
            let mut certifier_view = header.view;
            while let Some(bitmap) = certifying.as_ref().map(|qc| qc.signer_bitmap.clone()) {
                let Some((cursor_header, cursor_body)) = self.blocks.get(&cursor_hash) else {
                    break;
                };
                if !matches!(cursor_body, BlockBody::Complete(_)) {
                    break;
                }
                if self.finalized.contains_key(&cursor_header.height.value()) {
                    break;
                }
                chain.push((
                    cursor_hash,
                    bitmap,
                    cursor_header.height.value(),
                    cursor_header.view.value(),
                    certifier_view.value(),
                ));
                certifier_view = cursor_header.view;
                certifying.clone_from(&cursor_header.high_qc);
                cursor_hash = cursor_header.prev_block;
            }
        }
        // Jolteon two-chain commit (arXiv:2106.10362 §3): a block
        // commits only through a *consecutive* certified pair —
        // its certifying child must be exactly one view later
        // (`child.view == cursor.view + 1`). The lock-persistence
        // proof depends on adjacency: when the pair is consecutive,
        // no TC for the child's view can exist, so the first TC
        // above the pair is guaranteed to carry evidence from the
        // locked quorum. A nonconsecutive link leaves a gap where a
        // TC could form before the lock existed — the hidden-QC fork
        // this change fixes committed exactly such a link.
        //
        // Committing a block finalizes its whole certified prefix —
        // ancestors need no pair of their own — so the commit point
        // is the *newest* collected block whose link is consecutive;
        // everything below it commits with it. Entries above stay
        // uncommitted (they close only through their own future
        // consecutive pair, or as ancestors of a later commit).
        let commit_from = chain
            .iter()
            .position(|(_, _, _, cursor_view, certifier_view)| *certifier_view == *cursor_view + 1)
            .unwrap_or(chain.len());
        let chain = &chain[commit_from..];
        // Contiguity guard: commit only when the collected chain's
        // oldest block is the direct child of the commit tip.
        // A gap means an ancestor proposal is still in flight —
        // the QC that certifies this chain arrived before the
        // block body did (real networks reorder). Committing
        // anyway would finalize out of order AND permanently
        // orphan the missing height: later walks stop at the
        // finalized sibling and never reach back. Deferring is
        // safe — the walk re-runs on the next delivered QC, by
        // which time the body has landed via the vote path.
        let expected_next =
            self.last_committed.map_or(0, |(_, committed_height)| committed_height.value() + 1);
        let contiguous =
            chain.last().is_none_or(|(_, _, oldest_height, _, _)| *oldest_height == expected_next);
        // Commit oldest-first so `finalize_block` sees a
        // contiguous ascending prefix.
        if contiguous {
            for (hash, bitmap, _, _, _) in chain.iter().rev() {
                self.commit_block(*hash, bitmap);
            }
        }
    }

    /// Commit `block_hash`: look up the block, create a
    /// `FinalizedBlock`, call `app.finalize_block`, and store it.
    ///
    /// `signer_bitmap` is the committing QC's bitmap — bit `i` marks
    /// `validator_addresses()[i]` as a signer. It is resolved to
    /// staking addresses here so the app receives attendance in its
    /// own identity space, never in consensus-internal indices.
    ///
    /// Note: `next_height` is NOT advanced here — it was already
    /// advanced when the block was proposed (the 2-chain pipeline
    /// proposes before committing). The app's `next_proposal_height`
    /// advances here (via `finalize_block`).
    pub(crate) fn commit_block(&mut self, block_hash: Hash, signer_bitmap: &[u8]) {
        let Some((header, body)) = self.blocks.remove(&block_hash) else {
            return; // already committed or unknown
        };
        // Certify gate (dispersed broadcast): a block whose body is
        // still `Awaiting` reconstruction must never finalize —
        // the commit walk already skips it, this is the last-line
        // guard if a future path ever reaches here directly. Put
        // the entry back so a later `supply_body` can complete it.
        let BlockBody::Complete(proposal) = body else {
            self.blocks.insert(block_hash, (header, body));
            return;
        };
        let addresses = self.validator_set.validator_addresses();
        let signers: Vec<Address> = signer_bitmap
            .iter()
            .enumerate()
            .flat_map(|(byte_i, byte)| {
                (0..8).filter_map(move |bit| {
                    if byte & (1u8 << bit) != 0 {
                        addresses.get(byte_i * 8 + bit).copied()
                    } else {
                        None
                    }
                })
            })
            .collect();
        // The execution context every replica must agree on. All
        // three fields are derived from consensus-committed material,
        // never local state:
        //
        // - `timestamp_ms`: the header's own stamp — signed by the
        //   proposer and QC-certified, so every node reads the same
        //   value the leader committed.
        // - `beneficiary`: the proposer's staking address, recovered
        //   from `header.proposer` (the validator index is encoded in
        //   the hash — see `proposer_hash`) against this epoch's
        //   validator set. `Address::ZERO` when the index doesn't
        //   resolve — a header whose proposer passed authentication
        //   always resolves, so ZERO only marks conformance-shaped
        //   headers; modules read it as "no beneficiary".
        // - `gas_limit`: the block budget this engine enforced when
        //   building/processing proposals — the authoritative block
        //   capacity the EVM must run under. Config-derived (same on
        //   every correctly configured node) rather than
        //   header-carried, so it cannot be lied about per-block.
        let proposer_idx = u16::from_le_bytes([header.proposer.0[0], header.proposer.0[1]]);
        let beneficiary = self
            .validator_set
            .validator_addresses()
            .get(usize::from(proposer_idx))
            .copied()
            .unwrap_or(Address::ZERO);
        let context = types::BlockContext {
            timestamp_ms: header.timestamp,
            beneficiary,
            gas_limit: self.block_budget.max_gas,
        };
        let block = FinalizedBlock { height: header.height, txs: proposal.txs, signers, context };
        // Notify the commit listener before inserting into `finalized`
        // — the map prunes at `MAX_RETAINED_FINALIZED`, so external
        // consumers that need full history must observe commits here.
        if let Some(listener) = &self.commit_listener {
            listener(&block);
        }
        self.app.finalize_block(&block);
        self.finalized.insert(header.height.value(), block);
        // Record the committed anchor: the parent a proposal must
        // extend while `high_qc` is `None` (post-rotation boundary,
        // or a node that has committed but not yet adopted a QC).
        // It is persisted safety state (WalEntry/save_state), so the
        // advance must reach the WAL before any signature that
        // could act on it — which every signature path guarantees by
        // syncing first. The append is deferred (no fsync of its
        // own): a crash that loses it rolls `last_committed` back,
        // peers re-deliver the QC, and the commit walk re-commits —
        // the executor dedupes the re-finalize by its
        // `next_proposal_height` watermark, so the rollback window
        // cannot double-apply. A synced append here would still be
        // ordered before later signatures identically, so deferral
        // cannot append a *stale* anchor over a rotation either:
        // `append_wal_full(true)` at the boundary serializes live
        // state.
        self.last_committed = Some((block_hash, header.height));
        // A failed append latches `wal_failed` (C10): the commit is
        // already real in memory and cannot be undone, but signing
        // must stop — durable state may now trail emitted signatures.
        let _ = self.append_wal_deferred();
        // Prune per-height vote locks at-or-below the committed
        // height: a finalized prefix cannot be forked, so the lock
        // is no longer needed. Keeps the map bounded by the number
        // of in-flight (uncommitted) heights.
        self.voted_at_height.retain(|h, _| *h > header.height.value());
        // Prune attestation state at-or-below the committed height:
        // the committed prefix is final and needs no certification.
        // `exec_certs` keeps a generous retention window — a cert is
        // formed by whichever leader collected the attesting votes,
        // and that leader only gets to embed it on its *next* turn,
        // up to a full committee rotation (~n views) plus the
        // attestation lag (~2 views) later. Two rotations of margin
        // covers both without unbounded growth: certs are ~200 B and
        // only the newest embeddable one is ever chosen anyway.
        let committed_height = header.height.value();
        self.exec_attest_pool.retain(|h, _| *h > committed_height);
        let cert_floor = committed_height
            .saturating_sub(2 * u64::try_from(self.validator_set.n()).unwrap_or(u64::MAX));
        self.exec_certs.retain(|h, _| *h >= cert_floor);
        self.verified_exec_certs.retain(|h, _| *h >= cert_floor);
        // Prune the block store of stale proposals: a block at or
        // below the just-committed height can never be needed again
        // (the 2-chain rule only walks ancestors of the pending
        // block, which are strictly above). Without this, a
        // byzantine leader could flood `blocks` with never-committed
        // proposals and grow memory without bound — a memory DoS
        // on every validator.
        let committed = header.height.value();
        self.blocks.retain(|_, (h, _)| h.height.value() > committed);
        // Bound the in-memory finalized history. Full history lives
        // in the journal/backend; the engine's map exists for the
        // commit path and recent-height queries, so retaining the
        // newest `MAX_RETAINED_FINALIZED` heights keeps memory
        // bounded without changing consensus semantics.
        while self.finalized.len() > MAX_RETAINED_FINALIZED {
            self.finalized.pop_first();
        }
    }

    /// Clear all per-view state: collected votes and timeout
    /// signatures.
    ///
    /// This must be called on every view transition (advance,
    /// sync, TC-driven jump, QC catch-up). Stale votes from a
    /// previous view cause `ConflictingVote` errors when the new
    /// view's votes arrive. Stale timeout signatures from a
    /// previous view get aggregated into the new view's TC,
    /// producing an aggregate that fails verification (the
    /// signatures were for a different view) — peers reject the
    /// TC and the view-change stalls.
    pub(crate) fn clear_per_view_state(&mut self) {
        self.votes.fill(None);
        self.vote_count = 0;
        self.vote_stake = 0;
        self.timeout_signatures.fill(None);
    }
}
