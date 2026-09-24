//! Bounded signature-verification pool for the consensus pump.
//!
//! Why this exists: every wire message that carries BLS material —
//! a proposal's proposer signature + shard commitment, a timeout
//! signature and its attached QC/TC evidence, a standalone QC
//! aggregate, a timeout certificate's per-signer records — used to
//! verify *inline* on the single-threaded consensus loop. Cheap
//! admission gates (leader claims, dedupe, per-sender budgets)
//! bounded how much junk reached verification, but each admitted
//! verification still blocked the pump inside pairing code: one
//! Byzantine peer feeding admissible junk could starve honest
//! progress.
//!
//! The pool splits verification into three explicit phases so the
//! expensive cryptography never runs on the pump thread:
//!
//! 1. **Resolve** (pump): `engine.*_verify_context` reads the live
//!    committee and produces pure crypto material — keys, signing
//!    messages, quorum thresholds. `None` means conformance mode
//!    (nothing to offload) or an already-failed resolution — the
//!    pump falls back to the ordinary inline entry points, which
//!    apply the same checks.
//! 2. **Verify** (worker): a [`VerifyTask`] closure runs the
//!    pairings. It owns only the decoded message and the resolved
//!    material — it cannot touch engine state, so it cannot be
//!    influenced by it and cannot mutate it.
//! 3. **Apply** (pump): the verdict returns over a bounded channel
//!    and is applied through `engine.*_preverified`, which re-runs
//!    every state-dependent check (leader schedule, epoch, view
//!    ordering, quorum structure) before mutating. A stale or
//!    contradictory verdict is a no-op — the apply half is a
//!    function of *live* state plus the verdict, never of the
//!    intake-time snapshot alone.
//!
//! Fairness under flood: the job queue is bounded globally
//! ([`VERIFY_QUEUE_CAP`], [`VERIFY_QUEUE_MAX_BYTES`]), per
//! authenticated peer ([`VERIFY_INFLIGHT_PER_PEER`]), and by a
//! per-peer submit rate ([`VERIFY_SUBMIT_BUDGET_PER_SEC`]). One
//! flooding peer can therefore hold at most a handful of slots and
//! a bounded slice of worker throughput; its resubmits queue FIFO
//! behind honest work instead of starving it.

use codec::Encode;

/// Hard cap on queued+running jobs across all peers.
///
/// Unit: jobs. Origin: the audit hardening requires a *bounded*
/// verification pool — this is the memory/latency bound on the
/// backlog. Tradeoff: larger buys deeper burst absorption but
/// lengthens the worst-case wait an honest job sits behind queued
/// work (~cap × per-job cost ÷ workers); smaller drops more flood
/// traffic sooner — which is safe because every consensus message
/// re-arrives via gossip or sync, and an unsubmitted job mutates
/// nothing.
const VERIFY_QUEUE_CAP: usize = 128;

/// Byte bound on queued job payloads.
///
/// Unit: bytes. Origin: proposal jobs carry the full block body
/// for the commitment check, and a configured block can be tens of
/// MiB — a job-count cap alone under-bounds the queue's memory.
/// Tradeoff: 64 MiB admits ~4 max-size proposals or thousands of
/// certificate jobs while capping the pool's worst-case heap.
const VERIFY_QUEUE_MAX_BYTES: usize = 64 << 20;

/// Queued+running jobs a single authenticated peer may hold.
///
/// Unit: jobs per peer. Origin: the fairness requirement — the
/// queue is FIFO, so a peer whose jobs all verify quickly could
/// otherwise re-fill the queue faster than honest traffic
/// interleaves. 8 is one view's honest shape (a proposal, a
/// timeout, a QC, a TC) with headroom; a flood peer caps at 8
/// outstanding jobs no matter how fast it sends.
const VERIFY_INFLIGHT_PER_PEER: u32 = 8;

/// Submit-rate budget per authenticated peer.
///
/// Unit: jobs per second per peer. Origin: `in_flight` bounds
/// *concurrent* jobs but a peer cycling small jobs (bad
/// signatures complete in ~1–3 ms) could still submit hundreds
/// per second. 128/s is ~20× an honest peer's peak (a view
/// produces at most a few verifiable frames per member) yet small
/// enough that one flooding peer draws under ~1 worker-equivalent
/// on the heaviest job type (a committee-size TC ≈ 10–20 ms of
/// worker time).
const VERIFY_SUBMIT_BUDGET_PER_SEC: u32 = 128;

/// Worker threads the pool spawns by default.
///
/// Unit: threads. Origin: BLS pairings are CPU-bound, so the pool
/// needs real parallelism to absorb flood while the pump core
/// stays free — `available_parallelism − 1` leaves the pump its
/// core, clamped to [2, 8]: below 2 a single slow job serializes
/// all verification; above 8 the marginal worker idles (the
/// per-peer caps bound how much concurrent work can even exist).
fn default_workers() -> usize {
    std::thread::available_parallelism().map_or(2, |n| n.get().saturating_sub(1)).clamp(2, 8)
}

/// One unit of pooled verification work — a pure crypto closure.
///
/// The pump builds it from engine-resolved material plus the
/// decoded message; the worker executes it; whatever it proves is
/// encoded into the returned [`VerifyOutcome`]. It must capture no
/// engine state: everything it needs arrives by value.
pub(crate) type VerifyTask = Box<dyn FnOnce() -> VerifyOutcome + Send>;

/// A completed job — the authenticated peer it came from, its
/// payload size (for the byte-accounted queue bound), and the
/// verdict the pump applies.
pub(crate) struct VerifyDone {
    /// The transport-authenticated peer id that sent the message —
    /// carried through the job so `in_flight` accounting and any
    /// verdict-triggered replies stay bound to the proven sender.
    pub peer: Vec<u8>,
    /// `msg.bytes.len()` at intake — returned so the byte bound
    /// decrements exactly what it charged.
    pub payload_bytes: usize,
    /// The verdict payload the pump applies.
    pub outcome: VerifyOutcome,
}

/// What a pooled job proved — the message it ran over plus the
/// verdicts the pump applies through the engine's `*_preverified`
/// entries.
pub(crate) enum VerifyOutcome {
    /// A proposal's proposer-signature and shard-commitment
    /// verdicts — applied via `OxideBft::admit_preverified`.
    Proposal {
        /// The decoded header, returned for storage. Boxed: a
        /// header dwarfs the other variants' payloads and would
        /// size the whole enum — every outcome pays its bytes on
        /// the bounded results channel.
        header: Box<types::BlockHeader>,
        /// The decoded body, returned for storage.
        proposal: Box<types::Proposal>,
        /// Whether `header.proposer_signature` verified over the
        /// intake-resolved signing hash under the leader key.
        sig_ok: bool,
        /// Whether the body's shard commitment matched
        /// `header.body_commitment`.
        commit_ok: bool,
    },
    /// A timeout frame's signature + attached-evidence verdicts —
    /// applied via `deliver_qc_preverified`,
    /// `on_timeout_certificate_preverified`, and
    /// `collect_timeout_signature_preverified` in the same order
    /// the inline path uses.
    Timeout {
        /// The sender's committee seat (resolved at intake).
        voter: consensus::ValidatorIndex,
        /// The decoded timeout signature.
        signature: crypto::Signature,
        /// The view the signature claims.
        sig_view: u64,
        /// The epoch the signature claims.
        sig_epoch: u64,
        /// Whether the signature verified over
        /// `(sig_view, sig_epoch, qc_ev)` under the voter's key.
        sig_ok: bool,
        /// Attached QC evidence + which candidate committee (if
        /// any) verified it. `None` — the frame carried none.
        qc_ev: Option<(types::QuorumCertificate, consensus::QcVerdict)>,
        /// Attached TC evidence + whether every record and carried
        /// QC verified. `None` — the frame carried none.
        tc_ev: Option<(types::TimeoutCertificate, bool)>,
    },
    /// A standalone QC's aggregate verdict — applied via
    /// `deliver_qc_preverified`.
    Qc {
        /// The decoded certificate, returned for delivery.
        qc: types::QuorumCertificate,
        /// Which candidate committee verified it (or `Invalid`).
        verdict: consensus::QcVerdict,
    },
    /// A standalone TC's record verdict — applied via
    /// `on_timeout_certificate_preverified`.
    Tc {
        /// The decoded certificate, returned for delivery.
        tc: types::TimeoutCertificate,
        /// Whether every signer record and every distinct carried
        /// QC verified under the live committee.
        verified: bool,
    },
    /// A vote's execution-attestation verdict — applied via
    /// `apply_attest_verdict`. The vote itself already collected;
    /// only the attestation's pool insert rides this verdict.
    Attest {
        /// The attesting committee seat (resolved at intake).
        voter: consensus::ValidatorIndex,
        /// The claim the signature covers.
        attestation: types::StateAttestation,
        /// The signature the worker checked.
        signature: crypto::Signature,
        /// Whether the signature verified under the voter's key.
        verified: bool,
    },
}

/// The bounded worker pool. Owns the send half of the job queue,
/// the receive half of the results, and the fairness accounting —
/// workers are detached daemon threads that exit when the pump's
/// senders drop.
pub(crate) struct VerifyPool {
    jobs: crossbeam_channel::Sender<(Vec<u8>, usize, VerifyTask)>,
    results: crossbeam_channel::Receiver<VerifyDone>,
    /// Outstanding (queued + running) jobs per authenticated peer —
    /// the `VERIFY_INFLIGHT_PER_PEER` accounting.
    in_flight: std::collections::HashMap<Vec<u8>, u32>,
    /// Per-peer submit-rate windows — `(window_start, count)`,
    /// reset after a second elapses.
    submit_budget: std::collections::HashMap<Vec<u8>, (std::time::Instant, u32)>,
    /// Outstanding jobs total — the `VERIFY_QUEUE_CAP` accounting.
    queued_jobs: usize,
    /// Outstanding payload bytes — the `VERIFY_QUEUE_MAX_BYTES`
    /// accounting.
    queued_bytes: usize,
}

impl VerifyPool {
    /// Spawn the pool with [`default_workers`] threads.
    pub(crate) fn spawn() -> Self {
        Self::with_workers(default_workers())
    }

    /// Spawn the pool with an explicit worker count — tests pin
    /// this so behavior doesn't depend on the host's core count.
    pub(crate) fn with_workers(workers: usize) -> Self {
        // `bounded` on both halves: the job channel is the real
        // bound; the results channel's capacity only ever holds
        // completed work (≤ the job bound by construction), and a
        // bounded results channel keeps a dead pump from letting
        // workers queue outcomes without end.
        let (job_tx, job_rx) =
            crossbeam_channel::bounded::<(Vec<u8>, usize, VerifyTask)>(VERIFY_QUEUE_CAP);
        let (done_tx, done_rx) = crossbeam_channel::bounded::<VerifyDone>(VERIFY_QUEUE_CAP);
        for _ in 0..workers.max(1) {
            let rx = job_rx.clone();
            let done = done_tx.clone();
            // Detached, like every other pump-adjacent thread in
            // this crate: workers exit when the last job sender
            // drops (pool teardown on pump shutdown) or the result
            // channel dies. `thread::spawn` panics on resource
            // failure — consistent with the pump's own startup.
            std::thread::spawn(move || {
                while let Ok((peer, payload_bytes, task)) = rx.recv() {
                    if done.send(VerifyDone { peer, payload_bytes, outcome: task() }).is_err() {
                        // The pump is gone — no one can apply the
                        // verdict, so the worker's job is finished.
                        return;
                    }
                }
            });
        }
        Self {
            jobs: job_tx,
            results: done_rx,
            in_flight: std::collections::HashMap::new(),
            submit_budget: std::collections::HashMap::new(),
            queued_jobs: 0,
            queued_bytes: 0,
        }
    }

    /// Offer `task` to the pool on behalf of `peer` — the
    /// *transport-authenticated* id, never a wire-claimed field.
    /// `payload_bytes` is the wire frame's size, charged against
    /// the byte bound.
    ///
    /// Returns `false` — the caller drops the message — when any
    /// bound is hit: the peer already holds
    /// [`VERIFY_INFLIGHT_PER_PEER`] outstanding jobs, its
    /// per-second submit budget is spent, the global queue is full
    /// by jobs or bytes, or the channel disconnected (pump
    /// teardown). Dropping is always safe: every consensus message
    /// re-arrives via gossip or sync, and an unsubmitted job
    /// mutates nothing.
    pub(crate) fn submit(&mut self, peer: &[u8], payload_bytes: usize, task: VerifyTask) -> bool {
        let held = self.in_flight.get(peer).copied().unwrap_or(0);
        if held >= VERIFY_INFLIGHT_PER_PEER
            || self.queued_jobs >= VERIFY_QUEUE_CAP
            || self.queued_bytes.saturating_add(payload_bytes) > VERIFY_QUEUE_MAX_BYTES
        {
            return false;
        }
        let now = std::time::Instant::now();
        let budget = self.submit_budget.entry(peer.to_vec()).or_insert((now, 0));
        if budget.0.elapsed() >= std::time::Duration::from_secs(1) {
            *budget = (now, 0);
        }
        if budget.1 >= VERIFY_SUBMIT_BUDGET_PER_SEC {
            return false;
        }
        // `try_send` is the backstop for the accounting: the counts
        // above already bound the queue, so a failure here is a
        // disconnect (teardown) — or a bound disagreement, which
        // must drop rather than block the pump.
        if self.jobs.try_send((peer.to_vec(), payload_bytes, task)).is_err() {
            return false;
        }
        budget.1 += 1;
        *self.in_flight.entry(peer.to_vec()).or_insert(0) = held + 1;
        self.queued_jobs += 1;
        self.queued_bytes = self.queued_bytes.saturating_add(payload_bytes);
        true
    }

    /// Non-blocking drain — one completed job or `None`. Decrements
    /// the per-peer and global accounting; the pump calls this in a
    /// loop each iteration and applies each verdict.
    pub(crate) fn try_recv(&mut self) -> Option<VerifyDone> {
        let done = self.results.try_recv().ok()?;
        self.queued_jobs = self.queued_jobs.saturating_sub(1);
        self.queued_bytes = self.queued_bytes.saturating_sub(done.payload_bytes);
        if let Some(held) = self.in_flight.get_mut(&done.peer) {
            *held = held.saturating_sub(1);
            if *held == 0 {
                self.in_flight.remove(&done.peer);
            }
        }
        Some(done)
    }

    /// Outstanding queued+running jobs — tests observe the bound.
    #[cfg(test)]
    pub(crate) fn queued_jobs(&self) -> usize {
        self.queued_jobs
    }

    /// Outstanding jobs attributed to `peer` — tests observe the
    /// fairness bound.
    #[cfg(test)]
    pub(crate) fn in_flight_of(&self, peer: &[u8]) -> u32 {
        self.in_flight.get(peer).copied().unwrap_or(0)
    }
}

/// Fold a QC's candidate materials into a [`consensus::QcVerdict`]:
/// the first candidate whose quorum threshold and aggregate both
/// verify wins — the same current-then-pending order `deliver_qc`
/// tries inline. An empty material list (no bitmap resolved under
/// any held set) folds to `Invalid`.
fn qc_verdict(
    qc: &types::QuorumCertificate,
    materials: &[consensus::QcVerifyMaterial],
) -> consensus::QcVerdict {
    for m in materials {
        if consensus::qc_material_verifies(m, qc) {
            return if m.pending_set {
                consensus::QcVerdict::Pending
            } else {
                consensus::QcVerdict::Current
            };
        }
    }
    consensus::QcVerdict::Invalid
}

/// The whole-TC verdict: every signer record's timeout signature
/// over its own claim AND every distinct carried QC must verify —
/// the same conjunction `verify_tc_signature`'s crypto half runs.
fn tc_verified(material: &consensus::TcVerifyMaterial) -> bool {
    material
        .records
        .iter()
        .all(|(pk, msg, sig)| crypto::verify(sig, crypto::hash::Domain::Timeout, msg, pk).is_ok())
        && material.qcs.iter().all(|(qc, m)| consensus::qc_material_verifies(m, qc))
}

/// Build the proposal job: verify the proposer signature over the
/// intake-resolved signing hash, then encode the body and compare
/// the shard commitment — both pure functions of the material and
/// the message.
pub(crate) fn proposal_job(
    header: types::BlockHeader,
    proposal: types::Proposal,
    material: consensus::ProposalVerifyMaterial,
) -> VerifyTask {
    Box::new(move || {
        // The signature field's presence was already a context
        // precondition — re-checking costs nothing and keeps the
        // job self-contained (a verdict must stand on the bytes
        // alone).
        let sig_ok = header.proposer_signature.as_ref().is_some_and(|sig| {
            crypto::verify(
                sig,
                crypto::hash::Domain::Proposal,
                material.signing_hash.as_bytes(),
                &material.leader_pk,
            )
            .is_ok()
        });
        let commit_ok = {
            let mut buf = Vec::new();
            proposal.encode(&mut buf);
            types::shard::commitment(&buf, material.shard_count, material.shard_threshold)
                == header.body_commitment
        };
        VerifyOutcome::Proposal {
            header: Box::new(header),
            proposal: Box::new(proposal),
            sig_ok,
            commit_ok,
        }
    })
}

/// Build the timeout-frame job: verify the timeout signature over
/// the intake-resolved `(view, epoch, qc_high)` message, verify any
/// attached QC evidence through its candidate materials, and
/// verify any attached TC's records + carried QCs. A part the
/// frame didn't carry yields `None`; an unresolvable context
/// yields the failing verdict — never a pass.
pub(crate) fn timeout_job(
    voter: consensus::ValidatorIndex,
    signature: crypto::Signature,
    sig_view: u64,
    sig_epoch: u64,
    sig_ctx: (crypto::bls::PublicKey, [u8; 57]),
    qc_part: Option<(types::QuorumCertificate, Vec<consensus::QcVerifyMaterial>)>,
    tc_part: Option<(types::TimeoutCertificate, Option<consensus::TcVerifyMaterial>)>,
) -> VerifyTask {
    Box::new(move || {
        let sig_ok =
            crypto::verify(&signature, crypto::hash::Domain::Timeout, &sig_ctx.1, &sig_ctx.0)
                .is_ok();
        let qc_ev = qc_part.map(|(qc, materials)| {
            let verdict = qc_verdict(&qc, &materials);
            (qc, verdict)
        });
        let tc_ev = tc_part.map(|(tc, material)| {
            let verified = material.is_some_and(|m| tc_verified(&m));
            (tc, verified)
        });
        VerifyOutcome::Timeout { voter, signature, sig_view, sig_epoch, sig_ok, qc_ev, tc_ev }
    })
}

/// Build the standalone-QC job: fold the candidate materials into
/// a verdict — no resolution happens here, the pump resolved at
/// intake.
pub(crate) fn qc_job(
    qc: types::QuorumCertificate,
    materials: Vec<consensus::QcVerifyMaterial>,
) -> VerifyTask {
    Box::new(move || {
        let verdict = qc_verdict(&qc, &materials);
        VerifyOutcome::Qc { qc, verdict }
    })
}

/// Build the standalone-TC job: every record and distinct carried
/// QC in the material must verify.
pub(crate) fn tc_job(
    tc: types::TimeoutCertificate,
    material: consensus::TcVerifyMaterial,
) -> VerifyTask {
    Box::new(move || {
        let verified = tc_verified(&material);
        VerifyOutcome::Tc { tc, verified }
    })
}

/// Build the attestation job: verify the vote's `ExecAttest`
/// signature over the intake-resolved `(height, root, epoch)`
/// message — a pure function of the material.
pub(crate) fn attest_job(task: consensus::AttestVerifyTask) -> VerifyTask {
    Box::new(move || {
        let verified =
            crypto::verify(&task.signature, crypto::hash::Domain::ExecAttest, &task.msg, &task.pk)
                .is_ok();
        VerifyOutcome::Attest {
            voter: task.voter,
            attestation: task.attestation,
            signature: task.signature,
            verified,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bls_key(b: u8) -> crypto::BlsSecretKey {
        crypto::BlsSecretKey::from_ikm(&[b; 32]).expect("key gen")
    }

    fn dummy_tc() -> types::TimeoutCertificate {
        types::TimeoutCertificate {
            view: primitives::View::new(0),
            epoch: primitives::Epoch::new(0),
            signers: Vec::new(),
        }
    }

    /// A pool-mechanics job: reports a marker verdict inside a
    /// dummy TC. The pool's fairness/bounds logic is outcome-
    /// agnostic, so real crypto isn't needed for those tests.
    fn marker_job(verified: bool) -> VerifyTask {
        Box::new(move || VerifyOutcome::Tc { tc: dummy_tc(), verified })
    }

    /// A job that emulates real pairing cost before reporting.
    fn slow_marker_job(verified: bool, cost: std::time::Duration) -> VerifyTask {
        Box::new(move || {
            std::thread::sleep(cost);
            VerifyOutcome::Tc { tc: dummy_tc(), verified }
        })
    }

    fn header_with_sig(sig: crypto::Signature) -> types::BlockHeader {
        types::BlockHeader {
            height: primitives::Height::new(1),
            view: primitives::View::new(0),
            epoch: primitives::Epoch::new(0),
            prev_block: primitives::Hash::ZERO,
            tx_root: primitives::Hash([1; 32]),
            high_qc: None,
            timeout_cert: None,
            proposer: primitives::Hash([1; 32]),
            timestamp: 0,
            proposer_signature: Some(sig),
            exec_cert: None,
            body_commitment: primitives::Hash::ZERO,
        }
    }

    fn proposal(tag: u8) -> types::Proposal {
        types::Proposal {
            height: primitives::Height::new(1),
            txs: vec![types::TxBytes::new(vec![tag])],
            attestation: None,
        }
    }

    #[test]
    fn submitted_jobs_run_and_report() {
        let mut pool = VerifyPool::with_workers(1);
        assert!(pool.submit(b"peer-a", 64, marker_job(true)));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let done = loop {
            if let Some(done) = pool.try_recv() {
                break done;
            }
            assert!(std::time::Instant::now() < deadline, "job never completed");
            std::thread::yield_now();
        };
        assert_eq!(done.peer, b"peer-a");
        assert_eq!(done.payload_bytes, 64);
        match done.outcome {
            VerifyOutcome::Tc { verified, .. } => assert!(verified),
            _ => panic!("wrong outcome variant"),
        }
        assert_eq!(pool.queued_jobs(), 0);
        assert_eq!(pool.in_flight_of(b"peer-a"), 0);
    }

    /// The fairness bound: one peer holds at most
    /// `VERIFY_INFLIGHT_PER_PEER` outstanding jobs — its ninth
    /// submit fails while another peer's job still gets in.
    #[test]
    fn per_peer_in_flight_cap_preserves_fairness() {
        let mut pool = VerifyPool::with_workers(1);
        // Hold the single worker on a slow job so the byz's queued
        // jobs stay outstanding instead of draining.
        assert!(pool.submit(
            b"holder",
            1,
            slow_marker_job(true, std::time::Duration::from_secs(30))
        ));
        let byz = b"byz".to_vec();
        let mut accepted = 0u32;
        for _ in 0..(VERIFY_INFLIGHT_PER_PEER + 4) {
            if pool.submit(&byz, 1, marker_job(false)) {
                accepted += 1;
            }
        }
        assert_eq!(accepted, VERIFY_INFLIGHT_PER_PEER, "byz is capped at its slice");
        assert_eq!(pool.in_flight_of(&byz), VERIFY_INFLIGHT_PER_PEER);
        // A different peer is unaffected by the byz's occupancy.
        assert!(pool.submit(b"honest", 1, marker_job(true)), "honest peer still submits");
    }

    /// The rate bound: a peer cycling instantly-completing jobs
    /// (drained each time, so in-flight never binds) is still
    /// capped at `VERIFY_SUBMIT_BUDGET_PER_SEC` submissions per
    /// second — the resubmit-rate backstop the in-flight cap can't
    /// provide for fast jobs.
    #[test]
    fn submit_budget_caps_per_peer_rate() {
        let mut pool = VerifyPool::with_workers(2);
        let byz = b"byz".to_vec();
        let mut accepted = 0u32;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        for _ in 0..(VERIFY_SUBMIT_BUDGET_PER_SEC + 20) {
            if pool.submit(&byz, 1, marker_job(false)) {
                accepted += 1;
            }
            // Wait out each job so `in_flight` returns to zero —
            // the rate budget, not the in-flight cap, must be the
            // binding limit in this test.
            while pool.in_flight_of(&byz) > 0 {
                while pool.try_recv().is_some() {}
                std::thread::yield_now();
                assert!(std::time::Instant::now() < deadline, "drain stalled");
            }
        }
        assert_eq!(accepted, VERIFY_SUBMIT_BUDGET_PER_SEC);
    }

    /// The global bound: enough distinct peers each filling their
    /// per-peer slice eventually exhaust `VERIFY_QUEUE_CAP`, after
    /// which every submit fails — the queue can never grow without
    /// bound.
    #[test]
    fn global_queue_cap_bounds_total_backlog() {
        let mut pool = VerifyPool::with_workers(1);
        // One held worker job: everything else accumulates queued.
        assert!(pool.submit(
            b"holder",
            1,
            slow_marker_job(true, std::time::Duration::from_secs(30))
        ));
        let mut submitted = 0usize;
        'peers: for p in 0u16..64 {
            let peer = p.to_be_bytes().to_vec();
            for _ in 0..VERIFY_INFLIGHT_PER_PEER {
                if !pool.submit(&peer, 1, marker_job(false)) {
                    break 'peers;
                }
                submitted += 1;
            }
        }
        // 1 holder + cap queued == VERIFY_QUEUE_CAP outstanding.
        assert_eq!(submitted + 1, VERIFY_QUEUE_CAP);
        assert!(!pool.submit(b"late-peer", 1, marker_job(false)));
    }

    /// The byte bound: a proposal job's body counts against
    /// `VERIFY_QUEUE_MAX_BYTES` — oversized payload submissions
    /// refuse before the job count binds.
    #[test]
    fn byte_bound_caps_payload_memory() {
        let mut pool = VerifyPool::with_workers(1);
        assert!(!pool.submit(b"fat", VERIFY_QUEUE_MAX_BYTES + 1, marker_job(true)));
        assert!(pool.submit(b"fat", VERIFY_QUEUE_MAX_BYTES, marker_job(true)));
        assert!(!pool.submit(b"fat2", 1, marker_job(true)), "byte cap already spent");
    }

    /// The proposal job proves both halves off-thread: a real
    /// signature over the material's signing hash, and the body's
    /// shard commitment — wrong key or wrong body fails closed.
    #[test]
    fn proposal_job_verifies_signature_and_commitment() {
        let sk = bls_key(7);
        let signing_hash = primitives::Hash([42; 32]);
        let sig = sk.sign(crypto::hash::Domain::Proposal, signing_hash.as_bytes());
        let body = proposal(0xAA);
        let mut header = header_with_sig(sig);
        let mut buf = Vec::new();
        body.encode(&mut buf);
        header.body_commitment = types::shard::commitment(&buf, 4, 2);

        let material = consensus::ProposalVerifyMaterial {
            leader_pk: sk.public_key(),
            signing_hash,
            shard_count: 4,
            shard_threshold: 2,
        };
        let (h, p) = (header.clone(), body.clone());
        match proposal_job(h, p, material)() {
            VerifyOutcome::Proposal { sig_ok, commit_ok, .. } => {
                assert!(sig_ok, "real signature must verify");
                assert!(commit_ok, "matching commitment must verify");
            }
            _ => panic!("wrong outcome variant"),
        }

        // Wrong-key material → sig fails; corrupted commitment →
        // commit fails.
        let bad_key_material = consensus::ProposalVerifyMaterial {
            leader_pk: bls_key(9).public_key(),
            ..consensus::ProposalVerifyMaterial {
                leader_pk: sk.public_key(),
                signing_hash,
                shard_count: 4,
                shard_threshold: 2,
            }
        };
        match proposal_job(header.clone(), proposal(0xAA), bad_key_material)() {
            VerifyOutcome::Proposal { sig_ok, commit_ok, .. } => {
                assert!(!sig_ok && commit_ok);
            }
            _ => panic!("wrong outcome variant"),
        }
        let mut bad_body = proposal(0xBB);
        bad_body.txs.push(types::TxBytes::new(vec![0xCC]));
        let material = consensus::ProposalVerifyMaterial {
            leader_pk: sk.public_key(),
            signing_hash,
            shard_count: 4,
            shard_threshold: 2,
        };
        match proposal_job(header, bad_body, material)() {
            VerifyOutcome::Proposal { sig_ok, commit_ok, .. } => {
                assert!(sig_ok && !commit_ok, "changed body must not match the commitment");
            }
            _ => panic!("wrong outcome variant"),
        }
    }

    /// The QC job folds candidates in `deliver_qc` order — current
    /// first, pending second — and reports `Invalid` only when no
    /// candidate verifies.
    #[test]
    fn qc_job_folds_candidates_in_order() {
        let keys: Vec<crypto::BlsSecretKey> = (1..=3u8).map(bls_key).collect();
        let pks: Vec<crypto::bls::PublicKey> =
            keys.iter().map(crypto::BlsSecretKey::public_key).collect();
        let msg = [9u8; 49];
        let sigs: Vec<crypto::Signature> =
            keys.iter().map(|k| k.sign(crypto::hash::Domain::Vote, &msg)).collect();
        let agg = crypto::aggregate(&sigs).expect("aggregate");
        let qc = types::QuorumCertificate {
            view: primitives::View::new(0),
            phase: types::VotePhase::Prepare,
            block_hash: primitives::Hash([3; 32]),
            epoch: primitives::Epoch::new(0),
            signer_bitmap: vec![0x07],
            aggregate_signature: agg,
        };
        let material = |pending: bool| consensus::QcVerifyMaterial {
            signer_pks: pks.clone(),
            voting_power: 3,
            required_power: 3,
            msg,
            pending_set: pending,
        };
        match qc_job(qc.clone(), vec![material(false)])() {
            VerifyOutcome::Qc { verdict, .. } => {
                assert_eq!(verdict, consensus::QcVerdict::Current);
            }
            _ => panic!("wrong outcome variant"),
        }
        // Pending-only candidates still prove the QC — flagged so
        // the apply side knows which set verified.
        match qc_job(qc.clone(), vec![material(true)])() {
            VerifyOutcome::Qc { verdict, .. } => {
                assert_eq!(verdict, consensus::QcVerdict::Pending);
            }
            _ => panic!("wrong outcome variant"),
        }
        // Sub-quorum voting power fails the threshold half even
        // with a real aggregate; empty materials fold to Invalid.
        let weak = consensus::QcVerifyMaterial { voting_power: 1, ..material(false) };
        match qc_job(qc.clone(), vec![weak])() {
            VerifyOutcome::Qc { verdict, .. } => {
                assert_eq!(verdict, consensus::QcVerdict::Invalid);
            }
            _ => panic!("wrong outcome variant"),
        }
        match qc_job(qc, Vec::new())() {
            VerifyOutcome::Qc { verdict, .. } => {
                assert_eq!(verdict, consensus::QcVerdict::Invalid);
            }
            _ => panic!("wrong outcome variant"),
        }
    }

    /// The timeout job authenticates the signature AND each
    /// attached evidence part independently — a valid signature
    /// over a forged QC still reports the QC as `Invalid`, which
    /// is what makes the claim die at collect time.
    #[test]
    fn timeout_job_verifies_sig_and_each_evidence_part() {
        let sk = bls_key(4);
        let sig_msg = [7u8; 57];
        let sig = sk.sign(crypto::hash::Domain::Timeout, &sig_msg);

        let keys: Vec<crypto::BlsSecretKey> = (1..=3u8).map(bls_key).collect();
        let pks: Vec<crypto::bls::PublicKey> =
            keys.iter().map(crypto::BlsSecretKey::public_key).collect();
        let qc_msg = [9u8; 49];
        let sigs: Vec<crypto::Signature> =
            keys.iter().map(|k| k.sign(crypto::hash::Domain::Vote, &qc_msg)).collect();
        let good_qc = types::QuorumCertificate {
            view: primitives::View::new(0),
            phase: types::VotePhase::Prepare,
            block_hash: primitives::Hash([3; 32]),
            epoch: primitives::Epoch::new(0),
            signer_bitmap: vec![0x07],
            aggregate_signature: crypto::aggregate(&sigs).expect("aggregate"),
        };
        let good_material = vec![consensus::QcVerifyMaterial {
            signer_pks: pks,
            voting_power: 3,
            required_power: 3,
            msg: qc_msg,
            pending_set: false,
        }];

        match timeout_job(
            1,
            sig,
            5,
            0,
            (sk.public_key(), sig_msg),
            Some((good_qc, good_material)),
            Some((dummy_tc(), None)),
        )() {
            VerifyOutcome::Timeout { sig_ok, qc_ev, tc_ev, .. } => {
                assert!(sig_ok);
                assert_eq!(qc_ev.map(|(_, v)| v), Some(consensus::QcVerdict::Current));
                // An unresolvable TC context reports a failing
                // verdict — never a pass.
                assert_eq!(tc_ev.map(|(_, ok)| ok), Some(false));
            }
            _ => panic!("wrong outcome variant"),
        }

        // Wrong key → sig fails; evidence verdicts still compute
        // independently (the apply side drops the frame on the sig
        // verdict regardless).
        match timeout_job(1, sig, 5, 0, (bls_key(8).public_key(), sig_msg), None, None)() {
            VerifyOutcome::Timeout { sig_ok, qc_ev, tc_ev, .. } => {
                assert!(!sig_ok);
                assert!(qc_ev.is_none() && tc_ev.is_none());
            }
            _ => panic!("wrong outcome variant"),
        }
    }

    /// The acceptance property: a peer flooding forged-but-
    /// admissible jobs cannot keep an honest peer's verification
    /// from completing — the honest verdict lands while the flood
    /// is still capped in-flight, and the flood never exceeds its
    /// per-peer share.
    #[test]
    fn adversarial_flood_cannot_starve_honest_verification() {
        let mut pool = VerifyPool::with_workers(2);
        let byz = b"byz".to_vec();
        let honest = b"honest".to_vec();

        // Junk jobs cost a real pairing: a forged signature still
        // runs the full BLS verify before failing — exactly what a
        // Byzantine peer's forged proposals cost workers.
        let signing_hash = primitives::Hash([77; 32]);
        let junk_header = header_with_sig(crypto::Signature::ZERO);
        for _ in 0..VERIFY_INFLIGHT_PER_PEER {
            assert!(
                pool.submit(
                    &byz,
                    1024,
                    proposal_job(
                        junk_header.clone(),
                        proposal(0x11),
                        consensus::ProposalVerifyMaterial {
                            leader_pk: bls_key(3).public_key(),
                            signing_hash,
                            shard_count: 4,
                            shard_threshold: 2,
                        }
                    ),
                ),
                "byz fills only its slice"
            );
        }
        assert!(!pool.submit(&byz, 1024, marker_job(false)), "in-flight cap binds");

        // The honest peer's real proposal verifies promptly while
        // the byz's junk is still queued behind the cap.
        let honest_sk = bls_key(5);
        let mut honest_header = header_with_sig(
            honest_sk.sign(crypto::hash::Domain::Proposal, signing_hash.as_bytes()),
        );
        let body = proposal(0x22);
        let mut buf = Vec::new();
        body.encode(&mut buf);
        honest_header.body_commitment = types::shard::commitment(&buf, 4, 2);
        let honest_material = consensus::ProposalVerifyMaterial {
            leader_pk: honest_sk.public_key(),
            signing_hash,
            shard_count: 4,
            shard_threshold: 2,
        };
        assert!(pool.submit(&honest, 1024, proposal_job(honest_header, body, honest_material)));

        let start = std::time::Instant::now();
        let outcome = loop {
            if let Some(done) = pool.try_recv()
                && done.peer == honest
            {
                break done.outcome;
            }
            // Bounded absolutely: the byz can at most fill its
            // slice, so the honest job completes while junk still
            // waits. 10 s is a CI-stable ceiling for ~8 pairings.
            assert!(
                start.elapsed() < std::time::Duration::from_secs(10),
                "honest verification starved by the flood"
            );
            std::thread::yield_now();
        };
        match outcome {
            VerifyOutcome::Proposal { sig_ok, commit_ok, .. } => {
                assert!(sig_ok && commit_ok, "honest proposal verified through the flood");
            }
            _ => panic!("wrong outcome variant"),
        }
        assert!(pool.in_flight_of(&byz) <= VERIFY_INFLIGHT_PER_PEER);
    }

    /// Full intake→pool→drain→apply under flood: a byz peer
    /// saturates its in-flight slice with forged-proposal jobs
    /// while an honest peer's real proposal verifies, drains, and
    /// applies into a live engine — proving the bounded pool keeps
    /// the pump's verdict path live and the verdict lands on real
    /// consensus state, not a mock.
    #[test]
    fn flood_then_honest_verdict_applies_to_live_engine() {
        let assembled = crate::assemble_executor(&crate::NodeConfig::default());
        let sk = crypto::BlsSecretKey::from_ikm(&[7; 32]).expect("key");
        let vs = consensus::ValidatorSet::new(vec![sk.public_key()], vec![1])
            .expect("one-validator set");
        let app: std::sync::Arc<dyn ports::AppInterface> = assembled.app.clone();
        let mut engine = consensus::OxideBft::new(app, vs).with_secret_key(sk.clone());

        // A real proposal for view 0 — leader is the single seat.
        let signing_hash = primitives::Hash([3; 32]);
        let mut header = header_with_sig(crypto::Signature::ZERO);
        let body = proposal(0x33);
        let mut buf = Vec::new();
        body.encode(&mut buf);
        header.body_commitment = types::shard::commitment(&buf, 1, 1);
        header.proposer = consensus::proposer_hash(0);
        // Sign the REAL signing hash — the digest the engine's
        // context resolves and the worker verifies against.
        let real_signing = consensus::OxideBft::proposal_signing_hash(&header);
        header.proposer_signature =
            Some(sk.sign(crypto::hash::Domain::Proposal, real_signing.as_bytes()));
        // The intake resolves material from live engine state —
        // the exact call the pump makes.
        let material = engine
            .proposal_verify_context(&header)
            .expect("the real header resolves under the live set");

        let mut pool = VerifyPool::with_workers(2);
        let byz = b"flood-peer".to_vec();
        let honest = b"honest-peer".to_vec();
        // The flood: forged-signature proposals — real pairing cost
        // per job, capped at the per-peer slice.
        let junk_header = header_with_sig(crypto::Signature::ZERO);
        let junk_pk = crypto::BlsSecretKey::from_ikm(&[9; 32]).expect("key").public_key();
        for _ in 0..VERIFY_INFLIGHT_PER_PEER {
            assert!(pool.submit(
                &byz,
                2048,
                proposal_job(
                    junk_header.clone(),
                    proposal(0x11),
                    consensus::ProposalVerifyMaterial {
                        leader_pk: junk_pk,
                        signing_hash,
                        shard_count: 1,
                        shard_threshold: 1,
                    }
                ),
            ));
        }
        assert!(!pool.submit(&byz, 2048, marker_job(false)), "flood is capped");
        // The honest job still gets in — the cap is per-peer.
        assert!(pool.submit(&honest, 2048, proposal_job(header.clone(), body.clone(), material)));

        // Drain exactly as the pump does — skip flood verdicts,
        // apply the honest one through `admit_preverified`.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            if let Some(done) = pool.try_recv()
                && done.peer == honest
            {
                let VerifyOutcome::Proposal { header, proposal, sig_ok, commit_ok } = done.outcome
                else {
                    panic!("wrong outcome variant");
                };
                assert!(
                    engine.admit_preverified(&header, &proposal, sig_ok, commit_ok),
                    "honest proposal must admit under flood"
                );
                break;
            }
            assert!(std::time::Instant::now() < deadline, "honest verdict starved by the flood");
            std::thread::yield_now();
        }
    }
}
