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
    Address, BlockBody, BlockHeader, CertifiedBlock, ConsensusError, Encode, FinalizedBlock, Hash,
    MAX_RETAINED_FINALIZED, OxideBft, QuorumCertificate, SyncReject,
};

/// One committable link collected by [`OxideBft::commit_walk`]: a
/// stored block plus the certified pair that closes it — the
/// material a [`CertifiedBlock`] sync record is built from.
pub(crate) struct CommitLink {
    /// The block's hash (key into `self.blocks`).
    pub(crate) hash: Hash,
    /// The block's height — the contiguity guard's input.
    pub(crate) height: u64,
    /// The block's view — one half of the consecutive-pair rule.
    pub(crate) view: u64,
    /// The certifying child's view — the other half.
    pub(crate) certifier_view: u64,
    /// The certified child header: `child.prev_block == hash` and
    /// `child.view == view + 1` — the first link of the commit pair.
    pub(crate) child: BlockHeader,
    /// The QC certifying `child` — the second link. For the walk's
    /// first cursor this is the QC whose delivery triggered the
    /// walk; for later cursors it is the QC the previous cursor's
    /// child embedded (`certifying` of the previous iteration).
    pub(crate) qc: QuorumCertificate,
}

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
    ///
    /// `tip_qc` is the certificate that makes `header` certified —
    /// the QC whose adoption triggered this walk (`deliver_qc`'s
    /// argument, or `high_qc` when a completing body unblocks the
    /// walk). It is the commit proof's outer link for the first
    /// collected block: every committed block ships a
    /// [`CertifiedBlock`] carrying `(child, qc-on-child)`, and for
    /// the newest link that QC is `tip_qc` itself.
    pub(crate) fn commit_walk(&mut self, header: &BlockHeader, tip_qc: &QuorumCertificate) {
        // Execution-lag throttle: while the app reports its lane
        // saturated, defer the whole walk — finalizing into a lane
        // that cannot keep up would grow its unexecuted debt past
        // the bounded window. The deferral is safe because the walk
        // re-runs on the next delivered QC or completed body, and it
        // always re-collects from the newest tip down: nothing is
        // memoized, so a deferred commit catches up in one pass once
        // the lane drains.
        if self.app.exec_saturated() {
            return;
        }
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
        // close: the cursor plus its certifying child header and the
        // QC on that child — the two links a `CertifiedBlock` record
        // must expose so a peer can verify the commit independently.
        // The certifier is the stored child carrying the cursor's QC
        // (`header` for the first link, the previous cursor
        // thereafter); the QC on the certifier is `tip_qc` for the
        // first link and the previous iteration's `certifying` QC
        // thereafter (the QC on a cursor always lives in its child,
        // which is the next link's certifier).
        let mut chain: Vec<CommitLink> = Vec::new();
        if header.high_qc.as_ref().is_some_and(|qc| qc.block_hash == header.prev_block) {
            let mut cursor_hash = header.prev_block;
            let mut certifying = header.high_qc.clone();
            let mut certifier_view = header.view;
            let mut certifier_header = header.clone();
            let mut certifier_qc = tip_qc.clone();
            while let Some(qc_on_cursor) = certifying.take() {
                let Some((cursor_header, cursor_body)) = self.blocks.get(&cursor_hash) else {
                    break;
                };
                if !matches!(cursor_body, BlockBody::Complete(_)) {
                    break;
                }
                if self.finalized.contains_key(&cursor_header.height.value()) {
                    break;
                }
                chain.push(CommitLink {
                    hash: cursor_hash,
                    height: cursor_header.height.value(),
                    view: cursor_header.view.value(),
                    certifier_view: certifier_view.value(),
                    child: certifier_header,
                    qc: certifier_qc,
                });
                // The cursor becomes the next link's certifier: its
                // header is the child that carries the next cursor's
                // QC, and `qc_on_cursor` is the QC certifying it.
                certifier_header = cursor_header.clone();
                certifier_qc = qc_on_cursor;
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
            .position(|link| link.certifier_view == link.view + 1)
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
        // which time the body has landed via the vote path or via
        // certified block sync (`apply_certified_block`).
        let expected_next =
            self.last_committed.map_or(0, |(_, committed_height)| committed_height.value() + 1);
        let contiguous = chain.last().is_none_or(|link| link.height == expected_next);
        // Commit oldest-first so `finalize_block` sees a
        // contiguous ascending prefix.
        if contiguous {
            for link in chain.iter().rev() {
                // Per-block saturation check, not just at walk
                // entry: one walk over a long certified chain could
                // otherwise push arbitrarily many blocks past the
                // lane's bounded window in a single pass. The
                // uncommitted remainder stays stored and is
                // re-collected by the next walk.
                if self.app.exec_saturated() {
                    break;
                }
                self.commit_block(link);
            }
        }
    }

    /// Commit the block a [`CommitLink`] names: look it up in the
    /// block store, wrap it with the link's certified pair into a
    /// [`CertifiedBlock`], and run the shared finalize tail.
    ///
    /// The link's `notary_bitmap` is the QC-on-block signer bitmap —
    /// bit `i` marks `validator_addresses()[i]` as a signer of the
    /// notarization. It is resolved to staking addresses inside
    /// `record_committed` so the app receives attendance in its own
    /// identity space, never in consensus-internal indices.
    ///
    /// Note: `next_height` is NOT advanced here — it was already
    /// advanced when the block was proposed (the 2-chain pipeline
    /// proposes before committing). The app's `next_proposal_height`
    /// advances here (via `finalize_block`).
    pub(crate) fn commit_block(&mut self, link: &CommitLink) {
        let Some((header, body)) = self.blocks.remove(&link.hash) else {
            return; // already committed or unknown
        };
        // Certify gate (dispersed broadcast): a block whose body is
        // still `Awaiting` reconstruction must never finalize —
        // the commit walk already skips it, this is the last-line
        // guard if a future path ever reaches here directly. Put
        // the entry back so a later `supply_body` can complete it.
        let BlockBody::Complete(proposal) = body else {
            self.blocks.insert(link.hash, (header, body));
            return;
        };
        let record =
            CertifiedBlock { header, proposal, child: link.child.clone(), qc: link.qc.clone() };
        self.record_committed(record);
    }

    /// Finalize a [`CertifiedBlock`]: emit the app-facing
    /// `FinalizedBlock`, fire the commit listener, execute, and run
    /// every committed-height bookkeeping step (anchor, reputation
    /// window, WAL, pruning). Shared by the live commit path
    /// (`commit_block`) and the sync path (`apply_certified_block`) —
    /// both produce identical observable state for identical records,
    /// which is what makes a synced prefix indistinguishable from a
    /// locally committed one.
    fn record_committed(&mut self, record: CertifiedBlock) {
        let header = &record.header;
        // `child.high_qc` is the QC certifying `header` — its bitmap
        // is the attendance record `FinalizedBlock.signers` carries.
        // `apply_certified_block` checks the binding
        // (`child.high_qc.block_hash == hash(header)`); the commit
        // path constructs it so. `None` only marks a malformed sync
        // record — unreachable on verified paths, and an empty
        // bitmap fails closed to "no attendance data".
        let signer_bitmap =
            record.child.high_qc.as_ref().map_or(&[][..], |qc| qc.signer_bitmap.as_slice());
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
        let block_hash = Self::block_hash(header);
        let block = FinalizedBlock {
            height: header.height,
            txs: record.proposal.txs.clone(),
            signers,
            context,
        };
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
        // Leader-reputation window: this block's certifying-QC
        // bitmap is one committed-height sample of who participated.
        // Push before the deferred WAL append so the snapshot carries
        // it — the window is committed history, identical on every
        // replica that finalized the same prefix, and the restart
        // path must see the same exclusions it had pre-crash.
        self.recent_signers.push_back(signer_bitmap.to_vec());
        while self.recent_signers.len() > self.leader_rep_window() {
            self.recent_signers.pop_front();
        }
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
        // Emit the certified record for the block-sync server: the
        // pump drains `certified_out` into its durable serve store
        // each iteration. The cap mirrors `finalized` — an engine
        // whose records are never drained (tests, sims) drops the
        // oldest rather than growing without bound, which is sound:
        // below-window serving is the store's problem, not the
        // consensus state machine's.
        self.certified_out.push_back(record);
        while self.certified_out.len() > MAX_RETAINED_FINALIZED {
            self.certified_out.pop_front();
        }
    }

    /// Verify a fetched [`CertifiedBlock`] and stage it for
    /// commit — the sync-path counterpart of
    /// [`commit_walk`](Self::commit_walk), including its
    /// commit-by-descent rule.
    ///
    /// A syncing replica cannot trust the serving peer, so every
    /// link of the certified chain is rechecked locally, cheap
    /// checks before crypto:
    ///
    /// 1. **Recency** — an already-finalized height is idempotent
    ///    (`Ok(false)`); redelivery is normal under retries. A
    ///    height already staged is likewise a no-op.
    /// 2. **Epoch** — the QC verifies only against the committee
    ///    that signed it; a record from another epoch cannot be
    ///    checked here, so the caller must fall back to certified
    ///    state sync (weak-subjectivity checkpointing) instead.
    /// 3. **Frontier contiguity + anchor** — the record must extend
    ///    the verified frontier: `height == committed + 1` chaining
    ///    `last_committed`, or `height == staged_tip + 1` chaining
    ///    the staged record below it. A gap is refused rather than
    ///    queued — the caller buffers or re-fetches.
    /// 4. **Certified pair** — `child.prev_block == hash(header)`,
    ///    `child.height == header.height + 1`, `qc` certifies
    ///    `child`, and `child.high_qc` certifies `header` (the
    ///    notarization the child's voters checked before signing).
    ///    `child.view` must be strictly greater than `header.view`
    ///    — NOT exactly +1: interior ancestors commit *by descent*
    ///    (`commit_walk` line ~140 — the run's newest link seals a
    ///    consecutive pair, everything below rides), and during
    ///    timeout churn a committed block's child legitimately sits
    ///    several views ahead (the intervening views went to TCs).
    ///    Requiring adjacency here was the original design — it
    ///    rejected every churned history, permanently.
    /// 5. **Body binding** — `tx_root` and the dispersed-broadcast
    ///    `body_commitment` recomputed against the header, so the
    ///    served bytes are the exact body quorum attested.
    /// 6. **Proposer authentication** — the claimed committee seat
    ///    must resolve and the proposal signature must verify under
    ///    it. (Schedule equality is deliberately NOT checked: the
    ///    reputation-aware leader schedule reads `recent_signers`,
    ///    which a syncing node rebuilds from the very blocks it is
    ///    importing — enforcing it here could reject legitimate
    ///    history during catch-up. The QC quorum is the authority.)
    /// 7. **Crypto** — both QC aggregate signatures verify against
    ///    this epoch's committee (`verify_qc_with` covers quorum
    ///    weight + signature): the notarizing QC proves `header`
    ///    notarized, the outer QC proves `child` certified.
    ///
    /// **Commit rule (the safety load-bearing step):** a verified
    /// record proves only that `header` and `child` are notarized
    /// links — a notarized block can still be orphaned by a later
    /// timeout-certificate unlock. What makes `header` *committed*
    /// is the Jolteon seal: some record in the contiguous staged
    /// run whose own pair is consecutive (`child.view ==
    /// header.view + 1`). Every accepted record stages; whenever
    /// the staged run's newest seal exists, the whole contiguous
    /// prefix through that seal finalizes via `record_committed`
    /// — exactly the descent `commit_walk` performs on live QCs.
    /// An honest peer's committed tip always carries a consecutive
    /// pair (that is *why* it is the tip), so any complete served
    /// range ends in a seal.
    ///
    /// Returns `Ok(true)` when this call committed at least one
    /// height, `Ok(false)` when the record was a duplicate or is
    /// staged awaiting a seal.
    ///
    /// # Errors
    /// [`ConsensusError::SyncRejected`] for any structural or
    /// cryptographic mismatch, [`ConsensusError::SyncDeferred`] while
    /// the execution lane is saturated (the record was not staged —
    /// retry when the lane drains), [`ConsensusError::SyncEpoch`]
    /// for records signed under a committee this engine no longer
    /// holds.
    pub fn apply_certified_block(
        &mut self,
        record: &CertifiedBlock,
    ) -> Result<bool, ConsensusError> {
        let height = record.header.height.value();
        // 1. Idempotent: already finalized (covers both the
        //    `finalized` window and pruned history — `last_committed`
        //    is the authoritative high-water mark), or already
        //    verified into the staged run. Both early exits still
        //    attempt a drain: a previous one may have stalled on a
        //    saturated execution lane with verified work staged —
        //    any re-delivery is the cheapest resume signal.
        let committed_height = self.last_committed.map(|(_, h)| h.value());
        if committed_height.is_some_and(|c| height <= c) || self.finalized.contains_key(&height) {
            self.drain_staged_sync();
            return Ok(false);
        }
        if self.sync_staged.contains_key(&height) {
            self.drain_staged_sync();
            return Ok(false);
        }
        // 2. Same-epoch gate: the bitmap indexes THIS committee.
        //    Cross-epoch history is verifiable only by chaining
        //    through each rotation's certified handoff — state sync
        //    territory, not a per-block check.
        if record.header.epoch != self.epoch {
            return Err(ConsensusError::SyncEpoch {
                height,
                record_epoch: record.header.epoch,
                epoch: self.epoch,
            });
        }
        // Defer rather than verify-then-drop while the lane is
        // saturated: the caller retries, and the record is still
        // valid when it does. Checked before the crypto spend —
        // the queue pressure is the urgent signal.
        if self.app.exec_saturated() {
            return Err(ConsensusError::SyncDeferred { height });
        }
        // 3. Frontier contiguity + anchor: the record must extend
        //    the verified chain — either the committed tip (anchor
        //    `last_committed`, or `Hash::ZERO` at genesis like
        //    `propose` uses) or the staged record at `height - 1`.
        let frontier = self.sync_frontier();
        if height != frontier {
            return Err(ConsensusError::SyncRejected { height, reason: SyncReject::NotNext });
        }
        let expected_prev = if committed_height.is_some_and(|c| height == c + 1)
            || (committed_height.is_none() && height == 0)
        {
            self.last_committed.map_or(Hash::ZERO, |(hash, _)| hash)
        } else {
            // `height - 1` is staged by the frontier's contiguity.
            self.sync_staged.get(&(height - 1)).map_or(Hash::ZERO, |r| Self::block_hash(&r.header))
        };
        if record.header.prev_block != expected_prev {
            return Err(ConsensusError::SyncRejected {
                height,
                reason: SyncReject::AnchorMismatch,
            });
        }
        self.verify_certified_pair(record)?;
        // Verified — stage it, then commit the contiguous prefix
        // through the newest consecutive seal (commit-by-descent).
        self.sync_staged.insert(height, record.clone());
        Ok(self.drain_staged_sync())
    }

    /// Steps 4–7 of
    /// [`apply_certified_block`](Self::apply_certified_block): the
    /// certified pair, the body binding, the proposer signature,
    /// and both QC aggregates.
    fn verify_certified_pair(&self, record: &CertifiedBlock) -> Result<(), ConsensusError> {
        let height = record.header.height.value();
        // 4. The certified pair: `child` directly extends `header`,
        //    `qc` certifies `child`, and the child's embedded
        //    `high_qc` certifies `header`. Views must be strictly
        //    increasing — interior links carry non-consecutive
        //    views by design (see the commit rule in
        //    `apply_certified_block`'s doc).
        let block_hash = Self::block_hash(&record.header);
        let child_hash = Self::block_hash(&record.child);
        if record.child.prev_block != block_hash {
            return Err(ConsensusError::SyncRejected { height, reason: SyncReject::BrokenPair });
        }
        if record.child.height != record.header.height.saturating_next() {
            return Err(ConsensusError::SyncRejected {
                height,
                reason: SyncReject::MalformedCertificate,
            });
        }
        if record.child.view <= record.header.view {
            return Err(ConsensusError::SyncRejected {
                height,
                reason: SyncReject::NonConsecutiveViews,
            });
        }
        if record.qc.block_hash != child_hash
            || record.qc.view != record.child.view
            || record.qc.epoch != record.header.epoch
        {
            return Err(ConsensusError::SyncRejected {
                height,
                reason: SyncReject::MalformedCertificate,
            });
        }
        let Some(notary) = &record.child.high_qc else {
            return Err(ConsensusError::SyncRejected {
                height,
                reason: SyncReject::BrokenNotarization,
            });
        };
        if notary.block_hash != block_hash
            || notary.view != record.header.view
            || notary.epoch != record.header.epoch
        {
            return Err(ConsensusError::SyncRejected {
                height,
                reason: SyncReject::BrokenNotarization,
            });
        }
        // 5. Body binding: the proposal must be the exact bytes the
        //    header commits — `tx_root` over the tx list and the
        //    dispersed-broadcast `body_commitment` over the full
        //    proposal encoding, or a crafted body could execute
        //    under a valid proof. `proposal.height` is deliberately
        //    NOT compared to `header.height`: it is the app's own
        //    proposal counter (last-committed+1), which legitimately
        //    trails the header height inside the 2-chain pipeline —
        //    and it is already bound by `body_commitment`, so a
        //    forged value cannot be swapped in anyway.
        if Self::tx_root(&record.proposal.txs) != record.header.tx_root {
            return Err(ConsensusError::SyncRejected { height, reason: SyncReject::BodyMismatch });
        }
        let mut body_bytes = Vec::new();
        record.proposal.encode(&mut body_bytes);
        if types::shard::commitment(&body_bytes, self.validator_set.n(), self.erasure_k())
            != record.header.body_commitment
        {
            return Err(ConsensusError::SyncRejected { height, reason: SyncReject::BodyMismatch });
        }
        // 6. Proposer authentication: the claimed seat (the first two
        //    bytes of `proposer` — see `proposer_hash`) must resolve
        //    in this committee and the signature must verify under
        //    its key. The seat is committed by the header hash, so a
        //    forged record cannot borrow another member's signature.
        if self.verify_signatures {
            let seat =
                u16::from_le_bytes([record.header.proposer.0[0], record.header.proposer.0[1]]);
            let (Ok(pk), Some(sig)) =
                (self.validator_set.validator(seat), &record.header.proposer_signature)
            else {
                return Err(ConsensusError::SyncRejected {
                    height,
                    reason: SyncReject::BadProposerSignature,
                });
            };
            let signing_hash = Self::proposal_signing_hash(&record.header);
            if crypto::verify(sig, crypto::hash::Domain::Proposal, signing_hash.as_bytes(), pk)
                .is_err()
            {
                return Err(ConsensusError::SyncRejected {
                    height,
                    reason: SyncReject::BadProposerSignature,
                });
            }
        }
        // 7. Crypto: both links of the pair must clear quorum +
        //    aggregate verification against this committee —
        //    `verify_qc_with` is the same bar `deliver_qc` applies.
        self.verify_qc_with(&self.validator_set, notary)?;
        self.verify_qc_with(&self.validator_set, &record.qc)?;
        Ok(())
    }

    /// The height a fetched [`CertifiedBlock`] must have to be
    /// appliable — the first height neither committed nor staged.
    /// The pump fetches ranges from this frontier and applies
    /// buffered records when they reach it.
    pub fn sync_frontier(&self) -> u64 {
        self.sync_staged
            .keys()
            .next_back()
            .map_or_else(|| self.last_committed.map_or(0, |(_, h)| h.value() + 1), |tip| tip + 1)
    }

    /// Commit every staged record the newest consecutive seal
    /// covers — the sync-side mirror of `commit_walk`'s descent.
    ///
    /// A staged record whose own `(child, qc)` pair is consecutive
    /// (`child.view == header.view + 1`) seals a commit point: that
    /// header and every staged ancestor below it are committed.
    /// Returns whether anything committed. Stops early — leaving
    /// verified work staged — if the execution lane saturates
    /// mid-drain; the next `apply_certified_block` call resumes.
    fn drain_staged_sync(&mut self) -> bool {
        // The newest seal is the greatest staged height whose own
        // pair is consecutive. Staged heights are contiguous, so
        // the seal commits everything from the committed anchor up
        // through it by descent.
        let Some(seal) = self
            .sync_staged
            .iter()
            .rev()
            .find(|(_, r)| r.child.view.value() == r.header.view.value() + 1)
            .map(|(h, _)| *h)
        else {
            return false;
        };
        let mut committed_any = false;
        while let Some((&h, _)) = self.sync_staged.first_key_value() {
            if h > seal || self.app.exec_saturated() {
                break;
            }
            let Some((_, rec)) = self.sync_staged.pop_first() else {
                break;
            };
            let rec_height = rec.header.height;
            self.record_committed(rec);
            // `observe_block_height` keeps `next_height` above the
            // synced tip so this node never re-proposes a finalized
            // height when it becomes leader.
            self.observe_block_height(rec_height);
            committed_any = true;
        }
        committed_any
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
