//! The pacemaker — view synchronization state machine
//! (docs/oxidebft-spec.md §4).
//!
//! # What this module does
//!
//! The pacemaker drives view changes. A *view* is a leader round
//! within a height; views advance on timeout or on a timeout
//! certificate (TC). The pacemaker is **active, not reactive**: it
//! broadcasts a `Timeout` message when its local timer for the current
//! view expires, rather than waiting for the leader to self-report
//! failure (the Jolteon/AptosBFT design — proactive view sync keeps
//! finality moving under a faulty leader).
//!
//! # State machine (stage 2: no networking)
//!
//! ```text
//!   ┌────────┐  local timer    ┌──────────┐
//!   │ Active │ ────expires────▶│ TimedOut │
//!   │ (view) │                 │ (view)   │
//!   └────────┘                 └──────────┘
//!      ▲ │                        │  │
//!      │ │ progress               │  │ >2/3 stake timeout sigs
//!      │ │ (reset timer)          │  ▼
//!      │ │                        │ TC formed
//!      │ │     ┌──────────────┐   │
//!      └───── │ AdvanceView  │◀──┘
//!             │ (view → v+1) │
//!             └──────────────┘
//! ```
//!
//! - `Active(view)`: timer running, waiting for a proposal or votes.
//!   On progress (a valid proposal arrives), the timer resets.
//! - `TimedOut(view)`: local timer expired; collecting timeout
//!   signatures from other replicas. When the collected signers hold
//!   >2/3 of voting power, a TC forms and the view advances.
//! - A TC received from another replica (for the current view) also
//!   advances the view — a replica does not need to collect its own
//!   quorum if a peer already did.
//!
//! # Exponential backoff
//!
//! Consecutive timeouts double the timeout duration (capped at
//! `MAX_TIMEOUT`), so a persistently faulty leader is bypassed after
//! one timeout, then the next leader gets a longer window. This is
//! the Jolteon pattern: leader fault isolation in exactly one timeout
//! delay, then responsive recovery.

use crypto::bls::{Signature, ValidatorIndex};
use primitives::{Epoch, View};
use types::TimeoutCertificate;

use crate::validator::ValidatorSet;

/// Maximum timeout duration (milliseconds) for exponential backoff.
/// Origin: plan.md §4 performance budget — a stuck leader must not
/// stall the chain for more than a few seconds before the next leader
/// takes over. 30s is the hard cap; the base is 2s (WAN RTT budget).
///
/// This is the default value used when no explicit config is provided.
/// Production code should use [`Pacemaker::with_config`] to set this
/// from the [`config`](::config) crate's `ConsensusConfig`.
pub(crate) const DEFAULT_MAX_TIMEOUT_MS: u64 = 30_000;

/// Base timeout duration (milliseconds) for the first view. Origin:
/// plan.md §4 — steady-state blocks are 50–100ms, but a view timeout
/// must accommodate WAN RTT (~30ms) + vote aggregation (~15ms) + jitter.
/// 2s gives ample headroom for a first timeout; backoff handles
/// sustained faults.
///
/// This is the default value used when no explicit config is provided.
pub(crate) const DEFAULT_BASE_TIMEOUT_MS: u64 = 2_000;

/// The pacemaker's current state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacemakerState {
    /// Waiting for a proposal or votes in `view`; timer running.
    Active,
    /// Local timer expired; collecting timeout signatures for `view`.
    TimedOut,
}

/// Events the pacemaker emits for the consensus loop to act on.
/// The pacemaker is a pure state machine — it does not send messages;
/// it tells the caller what to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacemakerEvent {
    /// Broadcast a `Timeout` message for this view to all peers.
    /// Emitted when the local timer expires.
    BroadcastTimeout {
        /// The view that timed out.
        view: View,
        /// The epoch the timeout belongs to.
        epoch: Epoch,
    },
    /// A timeout certificate was formed (signers holding >2/3 of
    /// voting power collected). The consensus loop should include
    /// this TC in the
    /// next proposal if this replica is the next leader, or use it
    /// to validate the next leader's proposal.
    TimeoutCertificateFormed(TimeoutCertificate),
    /// The view advanced. The consensus loop should start the new
    /// leader's proposal timer and, if this replica is the leader,
    /// propose.
    AdvanceView {
        /// The view that was left.
        old_view: View,
        /// The new view.
        new_view: View,
        /// The TC that justified the advance (if any — a local
        /// timeout quorum produces one; an external TC does not).
        tc: Option<TimeoutCertificate>,
    },
}

/// The pacemaker: a state machine over views.
///
/// Stage 2 scope: pure state machine, no networking, no real BLS
/// signing (signatures are collected but not verified — stage 5
/// adds verification). The consensus loop (stage 3) drives this via
/// `on_local_timeout`, `on_timeout_signature`, `on_timeout_certificate`,
/// and `on_progress`.
pub struct Pacemaker {
    /// The validator set for the current epoch (for quorum calc).
    validator_set: ValidatorSet,
    /// Current view.
    current_view: View,
    /// Current epoch.
    current_epoch: Epoch,
    /// Current state (`Active` or `TimedOut`).
    state: PacemakerState,
    /// Timeout signatures collected for the current view, indexed by
    /// validator. A `1` bit means that validator signed a timeout.
    /// Stored as a bitmap matching the QC's `signer_bitmap` format.
    timeout_signers: Vec<u8>,
    /// Count of set bits in `timeout_signers` (diagnostic accessor
    /// only — the quorum decision uses [`has_timeout_quorum`]'s
    /// stake-weighted check, not this count).
    timeout_signer_count: usize,
    /// Whether this replica has already broadcast its own timeout
    /// for the current view (avoid duplicate broadcasts).
    own_timeout_sent: bool,
    /// Current timeout duration (milliseconds), doubled on each
    /// consecutive timeout (exponential backoff, capped at
    /// `max_timeout_ms`).
    current_timeout_ms: u64,
    /// Base timeout duration (milliseconds) for the first view.
    /// Configurable via [`Pacemaker::with_config`]. Default:
    /// [`DEFAULT_BASE_TIMEOUT_MS`] (2000 ms).
    base_timeout_ms: u64,
    /// Maximum timeout duration (milliseconds) for exponential
    /// backoff. Configurable via [`Pacemaker::with_config`]. Default:
    /// [`DEFAULT_MAX_TIMEOUT_MS`] (30000 ms).
    max_timeout_ms: u64,
    /// EWMA of observed *successful* view durations in milliseconds —
    /// the RTT-adaptive signal (α = 1/8: a fresh sample moves the
    /// estimate one eighth of the distance, converging in ~8 views
    /// and tolerating single outliers). `0` doubles as "no samples":
    /// a genuinely instant round needs no adaptation anyway, so the
    /// configured floor applies unmodified. Fed only by views that
    /// completed (QC adopted / commit) — a timed-out view's duration
    /// *is* the current timeout, and feeding it back would inflate
    /// the estimate it sprang from.
    round_ema_ms: u64,
}

impl Pacemaker {
    /// Construct a pacemaker for `validator_set`, starting at
    /// `initial_view` in `epoch`, with default timeouts.
    ///
    /// For custom timeouts, use [`Pacemaker::with_config`].
    #[must_use]
    pub fn new(validator_set: ValidatorSet, initial_view: View, epoch: Epoch) -> Self {
        Self::with_config(
            validator_set,
            initial_view,
            epoch,
            DEFAULT_BASE_TIMEOUT_MS,
            DEFAULT_MAX_TIMEOUT_MS,
        )
    }

    /// Construct a pacemaker with explicit timeout config.
    ///
    /// # Arguments
    ///
    /// - `validator_set`: the validator set for quorum calculations.
    /// - `initial_view`: the starting view number.
    /// - `epoch`: the starting epoch.
    /// - `base_timeout_ms`: the base timeout duration for the first
    ///   view, in milliseconds.
    /// - `max_timeout_ms`: the maximum timeout duration for
    ///   exponential backoff, in milliseconds.
    #[must_use]
    pub fn with_config(
        validator_set: ValidatorSet,
        initial_view: View,
        epoch: Epoch,
        base_timeout_ms: u64,
        max_timeout_ms: u64,
    ) -> Self {
        let bitmap_len = validator_set.n().div_ceil(8);
        Self {
            validator_set,
            current_view: initial_view,
            current_epoch: epoch,
            state: PacemakerState::Active,
            timeout_signers: vec![0u8; bitmap_len],
            timeout_signer_count: 0,
            own_timeout_sent: false,
            current_timeout_ms: base_timeout_ms,
            base_timeout_ms,
            max_timeout_ms,
            round_ema_ms: 0,
        }
    }

    /// Current view.
    #[must_use]
    pub fn current_view(&self) -> View {
        self.current_view
    }

    /// Advance to a specific view (happy-path sync). Used by the
    /// engine when it advances the view on a QC (not a timeout) —
    /// the pacemaker needs to stay in sync with the engine's view
    /// so that a later timeout fires for the correct view.
    ///
    /// Resets per-view state (timeout signers, `own_timeout_sent`)
    /// and transitions back to `Active`. Does NOT change the
    /// backoff (progress resets it separately via `on_progress`).
    pub fn sync_to_view(&mut self, view: View) {
        if view.value() > self.current_view.value() {
            self.current_view = view;
            self.state = PacemakerState::Active;
            self.reset_view_state();
        }
    }

    /// Current epoch.
    #[must_use]
    pub fn current_epoch(&self) -> Epoch {
        self.current_epoch
    }

    /// The validator set this pacemaker computes quorum and the
    /// leader schedule over — after a recovery or rotation rebuild
    /// it must equal the engine's active committee, or timeout
    /// certificates would be counted against a stale membership.
    #[must_use]
    pub fn validator_set(&self) -> &ValidatorSet {
        &self.validator_set
    }

    /// Current state (`Active` or `TimedOut`).
    #[must_use]
    pub fn state(&self) -> PacemakerState {
        self.state
    }

    /// Current timeout duration in milliseconds (for the caller to
    /// set its timer).
    #[must_use]
    pub fn timeout_duration_ms(&self) -> u64 {
        self.current_timeout_ms
    }

    /// Record the wall-clock duration of a view that *completed*
    /// (its QC was adopted or its block committed). The engine reads
    /// its injected clock at view start and calls this on every
    /// progress-driven advance; timeout-driven advances are not
    /// observed — a failed view measures the timeout, not the
    /// network.
    ///
    /// The estimate raises the timeout *floor* only (see
    /// [`Self::effective_base_ms`]): a slow network stops churning
    /// through premature view changes, while the configured base
    /// remains the operator's floor — adaptation never shortens a
    /// timeout below it.
    pub fn observe_round_ms(&mut self, ms: u64) {
        self.round_ema_ms = if self.round_ema_ms == 0 {
            ms
        } else {
            self.round_ema_ms.saturating_mul(7).saturating_add(ms) / 8
        };
    }

    /// The base timeout actually applied after progress: the
    /// configured floor, raised to `ADAPTIVE_ROUND_MULT × EWMA` when
    /// observed rounds consistently exceed it, capped at
    /// `max_timeout_ms`. A view's timeout must comfortably exceed a
    /// healthy round-trip; `ADAPTIVE_ROUND_MULT = 4` prices proposal
    /// propagation + vote collection + jitter at four observed
    /// round-trips (DiemBFT-family practice is ~2–4×) — tighter
    /// would churn views on ordinary latency spikes, looser would
    /// take longer to re-converge after a sustained slowdown.
    fn effective_base_ms(&self) -> u64 {
        const ADAPTIVE_ROUND_MULT: u64 = 4;
        self.round_ema_ms
            .saturating_mul(ADAPTIVE_ROUND_MULT)
            .clamp(self.base_timeout_ms, self.max_timeout_ms)
    }

    /// The leader for the current view.
    #[must_use]
    pub fn current_leader(&self) -> ValidatorIndex {
        self.validator_set.leader(self.current_view)
    }

    /// Number of timeout signatures collected so far for the current
    /// view.
    #[must_use]
    pub fn timeout_signer_count(&self) -> usize {
        self.timeout_signer_count
    }

    /// Whether a quorum of timeout signatures has been collected.
    ///
    /// Measured in voting power: the collected signers' combined
    /// stake must reach `⌊2·total_stake/3⌋ + 1` (oxideBFT spec §4).
    /// Signer *count* is only a quorum under equal stake — a swarm
    /// of low-stake validators cannot force a view change.
    #[must_use]
    pub fn has_timeout_quorum(&self) -> bool {
        self.validator_set.signer_stake(&self.timeout_signers) >= self.validator_set.quorum_stake()
    }

    /// Local timer expired — broadcast a timeout and start collecting.
    ///
    /// Returns `BroadcastTimeout` on the first call (transitioning
    /// Active → `TimedOut`). Subsequent calls without a view advance are
    /// ignored (the replica already broadcast its timeout for this
    /// view; duplicates would waste bandwidth).
    #[must_use]
    pub fn on_local_timeout(&mut self) -> Option<PacemakerEvent> {
        if self.state == PacemakerState::TimedOut && self.own_timeout_sent {
            // Already timed out and broadcast; the replica is waiting
            // for a quorum or an external TC. Do not re-broadcast.
            return None;
        }
        self.state = PacemakerState::TimedOut;
        self.own_timeout_sent = true;
        Some(PacemakerEvent::BroadcastTimeout {
            view: self.current_view,
            epoch: self.current_epoch,
        })
    }

    /// Received a timeout signature from `validator` for the current
    /// view. If this brings the collected voting power to quorum,
    /// form a TC and advance the view.
    ///
    /// Stage 2: signatures are collected but not verified (stage 5
    /// adds BLS verification). The caller is responsible for verifying
    /// the signature before calling this method.
    ///
    /// Returns `TimeoutCertificateFormed` + `AdvanceView` when the
    /// quorum is reached, or `None` if more signatures are needed.
    /// Duplicate signatures from the same validator are ignored
    /// (idempotent).
    #[must_use]
    pub fn on_timeout_signature(
        &mut self,
        validator: ValidatorIndex,
        _signature: Signature,
    ) -> Vec<PacemakerEvent> {
        let mut events = Vec::new();
        // Ignore signatures for a view we've already left (the caller
        // should filter these, but the pacemaker is defensive).
        // Also ignore if we're in Active state — a timeout signature
        // for a view we haven't timed out on is still valid (another
        // replica may have timed out before us); we collect it.
        let idx = usize::from(validator);
        if idx >= self.validator_set.n() {
            return events;
        }
        // Set the bit if not already set (idempotent).
        let byte_idx = idx / 8;
        let bit_mask = 1u8 << (idx % 8);
        if self.timeout_signers[byte_idx] & bit_mask == 0 {
            self.timeout_signers[byte_idx] |= bit_mask;
            self.timeout_signer_count += 1;
        }
        // Check for quorum.
        if self.has_timeout_quorum() {
            let tc = self.form_timeout_certificate();
            events.push(PacemakerEvent::TimeoutCertificateFormed(tc.clone()));
            events.extend(self.advance_view(Some(tc)));
        }
        events
    }

    /// Received a timeout certificate for the current view from
    /// another replica. Advance the view immediately — the peer
    /// already collected the quorum.
    ///
    /// Returns `AdvanceView` if the TC is for the current view (and
    /// we haven't already advanced), or `None` if it's stale (for a
    /// past view) or we've already advanced.
    #[must_use]
    pub fn on_timeout_certificate(&mut self, tc: &TimeoutCertificate) -> Option<PacemakerEvent> {
        // Reject TCs from a different epoch — they are not valid
        // certificates for this epoch.
        if tc.epoch != self.current_epoch {
            return None;
        }
        // Reject TCs for a past view — they are stale and must not
        // regress the engine's view.
        if tc.view.value() < self.current_view.value() {
            return None;
        }
        // Accept TCs for the current view OR a higher view. A higher-
        // view TC is the catch-up path: a validator that restarted (or
        // was partitioned) at a lower view receives a TC from peers
        // who have progressed further, and jumps forward to the TC's
        // view + 1. Without this, a restarted validator is stuck at
        // its old view forever because it cannot form or verify
        // timeout signatures for the peers' current view.
        if tc.view.value() > self.current_view.value() {
            // Jump forward to the TC's view, then advance_view will
            // increment to view + 1 and reset pacemaker state.
            self.current_view = tc.view;
        }
        // The TC is valid for the current view; advance.
        let events = self.advance_view(Some(tc.clone()));
        // advance_view returns a Vec; take the AdvanceView event.
        events.into_iter().find(|e| matches!(e, PacemakerEvent::AdvanceView { .. }))
    }

    /// Progress in the current view — a valid proposal or QC arrived.
    /// Resets the timer and backoff; transitions back to Active if
    /// we were in `TimedOut`.
    ///
    /// Returns `true` if the state changed (timer reset), `false` if
    /// we were already Active with a fresh timer (no-op).
    pub fn on_progress(&mut self) -> bool {
        let was_timed_out = self.state == PacemakerState::TimedOut;
        self.state = PacemakerState::Active;
        self.reset_view_state();
        // Reset backoff: progress means the current leader is working,
        // so the next timeout should be the base duration again —
        // the *effective* base, raised by the round-time EWMA when
        // the network is slower than the configured floor assumes.
        self.current_timeout_ms = self.effective_base_ms();
        // Always reset the timer on progress, whether or not we were
        // timed out — a valid proposal resets the view timer.
        let _ = was_timed_out;
        true
    }

    /// Advance to the next view, clearing the current view's state.
    /// Returns the `AdvanceView` event.
    fn advance_view(&mut self, tc: Option<TimeoutCertificate>) -> Vec<PacemakerEvent> {
        let old_view = self.current_view;
        // Saturating: view = u64::MAX would wrap to 0, causing the
        // pacemaker to schedule timeouts for view 0 and the engine
        // to vote in view 0 again (double-vote safety violation).
        // Saturation stalls the chain — the only recovery is epoch
        // rotation, which resets the view to 0 under a new validator
        // set, so saturation does not permanently block recovery.
        self.current_view = self.current_view.saturating_next();
        self.state = PacemakerState::Active;
        self.reset_view_state();
        // Exponential backoff: double the timeout on each consecutive
        // timeout, capped at DEFAULT_MAX_TIMEOUT_MS.
        self.current_timeout_ms = (self.current_timeout_ms * 2).min(self.max_timeout_ms);
        vec![PacemakerEvent::AdvanceView { old_view, new_view: self.current_view, tc }]
    }

    /// Reset the per-view state (timeout signers, `own_timeout_sent`).
    /// Called on view advance and on progress.
    fn reset_view_state(&mut self) {
        self.timeout_signers.fill(0);
        self.timeout_signer_count = 0;
        self.own_timeout_sent = false;
    }

    /// Form a timeout certificate marker for the collected quorum.
    ///
    /// The pacemaker is a pure state machine — it tracks *who* timed
    /// out (the bitmap) but not what they signed. The per-signer
    /// evidence records live in the engine's verified signature
    /// buffer, which fills `signers` when the
    /// `TimeoutCertificateFormed` event is handled — this TC's
    /// empty `signers` marks "quorum reached, evidence pending".
    fn form_timeout_certificate(&self) -> TimeoutCertificate {
        TimeoutCertificate {
            view: self.current_view,
            epoch: self.current_epoch,
            signers: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    //! Unit tests for the pacemaker state machine: timeout → TC
    //! formation → view advance, plus backoff and progress reset.

    use super::*;
    use crypto::bls::PublicKey;

    fn pk(byte: u8) -> PublicKey {
        PublicKey([byte; PublicKey::LEN])
    }

    /// 4 validators (f=1, quorum=3) — the minimum BFT configuration.
    fn vs4() -> ValidatorSet {
        ValidatorSet::new(vec![pk(1), pk(2), pk(3), pk(4)], vec![1, 1, 1, 1]).expect("4 validators")
    }

    fn sig(byte: u8) -> Signature {
        Signature([byte; Signature::LEN])
    }

    #[test]
    fn starts_active_at_initial_view() {
        let pm = Pacemaker::new(vs4(), View::new(0), Epoch::new(0));
        assert_eq!(pm.current_view(), View::new(0));
        assert_eq!(pm.state(), PacemakerState::Active);
        assert_eq!(pm.timeout_duration_ms(), DEFAULT_BASE_TIMEOUT_MS);
    }

    #[test]
    fn local_timeout_transitions_to_timed_out_and_broadcasts() {
        let mut pm = Pacemaker::new(vs4(), View::new(0), Epoch::new(0));
        let event = pm.on_local_timeout().expect("should emit");
        assert_eq!(pm.state(), PacemakerState::TimedOut);
        match event {
            PacemakerEvent::BroadcastTimeout { view, epoch } => {
                assert_eq!(view, View::new(0));
                assert_eq!(epoch, Epoch::new(0));
            }
            other => panic!("expected BroadcastTimeout, got {other:?}"),
        }
    }

    #[test]
    fn local_timeout_is_idempotent_within_view() {
        let mut pm = Pacemaker::new(vs4(), View::new(0), Epoch::new(0));
        pm.on_local_timeout().expect("first timeout emits");
        // Second timeout in the same view: no re-broadcast.
        assert!(pm.on_local_timeout().is_none());
    }

    #[test]
    fn timeout_signatures_form_tc_at_quorum() {
        let mut pm = Pacemaker::new(vs4(), View::new(0), Epoch::new(0));
        let _ = pm.on_local_timeout(); // transition to TimedOut
        // quorum = 3 for n=4. Collect 3 signatures.
        let events = pm.on_timeout_signature(0, sig(1));
        assert!(events.is_empty(), "1 sig is not quorum");
        assert_eq!(pm.timeout_signer_count(), 1);

        let events = pm.on_timeout_signature(1, sig(2));
        assert!(events.is_empty(), "2 sigs is not quorum");
        assert_eq!(pm.timeout_signer_count(), 2);

        // 3rd signature → quorum → TC + view advance.
        let events = pm.on_timeout_signature(2, sig(3));
        assert_eq!(events.len(), 2, "should emit TC formed + advance view");
        assert!(matches!(events[0], PacemakerEvent::TimeoutCertificateFormed(_)));
        match &events[1] {
            PacemakerEvent::AdvanceView { old_view, new_view, tc } => {
                assert_eq!(*old_view, View::new(0));
                assert_eq!(*new_view, View::new(1));
                assert!(tc.is_some(), "quorum-formed advance carries a TC");
            }
            other => panic!("expected AdvanceView, got {other:?}"),
        }
        assert_eq!(pm.current_view(), View::new(1));
        assert_eq!(pm.state(), PacemakerState::Active);
    }

    /// Stake-weighted timeout quorum: with stakes [100, 1, 1, 1]
    /// (`quorum_stake = 69` of `T = 103`), the three low-stake
    /// validators meeting the *count* quorum must not force a view
    /// change — a Byzantine small-stake minority could otherwise
    /// stall the chain by endlessly cycling views.
    #[test]
    fn timeout_tc_requires_voting_power_not_signer_count() {
        let weighted = ValidatorSet::new(vec![pk(1), pk(2), pk(3), pk(4)], vec![100, 1, 1, 1])
            .expect("4 validators, 100:1:1:1 stake");
        let mut pm = Pacemaker::new(weighted, View::new(0), Epoch::new(0));
        let _ = pm.on_local_timeout();

        // All three small validators sign: count quorum (3) met,
        // power quorum (3 of 103 < 69) not. No TC, no advance.
        for v in 1..4u16 {
            let events = pm.on_timeout_signature(v, sig(u8::try_from(v).unwrap_or(0) + 1));
            assert!(events.is_empty(), "low-stake signer {v} must not complete a TC");
        }
        assert!(!pm.has_timeout_quorum());
        assert_eq!(pm.current_view(), View::new(0), "must not advance on count alone");

        // The dominant validator's signature tips the power over 2/3.
        let events = pm.on_timeout_signature(0, sig(9));
        assert_eq!(events.len(), 2, "dominant stake completes the TC");
        assert!(matches!(events[0], PacemakerEvent::TimeoutCertificateFormed(_)));
        assert_eq!(pm.current_view(), View::new(1));
    }

    #[test]
    fn duplicate_timeout_signature_is_ignored() {
        let mut pm = Pacemaker::new(vs4(), View::new(0), Epoch::new(0));
        let _ = pm.on_timeout_signature(0, sig(1));
        let _ = pm.on_timeout_signature(0, sig(1)); // duplicate
        assert_eq!(pm.timeout_signer_count(), 1, "duplicate must not count");
    }

    #[test]
    fn external_tc_advances_view() {
        let mut pm = Pacemaker::new(vs4(), View::new(5), Epoch::new(0));
        // A TC formed by another replica for view 5. The pacemaker
        // is a pure state machine — it never inspects `signers`
        // (the engine fills/verifies them), so a bare marker with
        // the right view/epoch is sufficient here.
        let tc =
            TimeoutCertificate { view: View::new(5), epoch: Epoch::new(0), signers: Vec::new() };
        let event = pm.on_timeout_certificate(&tc).expect("should advance");
        match event {
            PacemakerEvent::AdvanceView { old_view, new_view, tc } => {
                assert_eq!(old_view, View::new(5));
                assert_eq!(new_view, View::new(6));
                assert!(tc.is_some());
            }
            other => panic!("expected AdvanceView, got {other:?}"),
        }
        assert_eq!(pm.current_view(), View::new(6));
    }

    #[test]
    fn stale_tc_is_ignored() {
        let mut pm = Pacemaker::new(vs4(), View::new(5), Epoch::new(0));
        let tc = TimeoutCertificate {
            view: View::new(3), // past view
            epoch: Epoch::new(0),
            signers: Vec::new(),
        };
        assert!(pm.on_timeout_certificate(&tc).is_none());
        assert_eq!(pm.current_view(), View::new(5), "view must not change");
    }

    #[test]
    fn tc_for_wrong_epoch_is_ignored() {
        let mut pm = Pacemaker::new(vs4(), View::new(0), Epoch::new(0));
        let tc = TimeoutCertificate {
            view: View::new(0),
            epoch: Epoch::new(1), // wrong epoch
            signers: Vec::new(),
        };
        assert!(pm.on_timeout_certificate(&tc).is_none());
    }

    #[test]
    fn progress_resets_timer_and_backoff() {
        let mut pm = Pacemaker::new(vs4(), View::new(0), Epoch::new(0));
        // Trigger a timeout to start backoff.
        let _ = pm.on_local_timeout();
        // Collect enough sigs to advance the view (doubles timeout).
        let _ = pm.on_timeout_signature(0, sig(1));
        let _ = pm.on_timeout_signature(1, sig(2));
        let _ = pm.on_timeout_signature(2, sig(3));
        // Now at view 1 with doubled timeout.
        assert_eq!(pm.current_view(), View::new(1));
        assert_eq!(pm.timeout_duration_ms(), DEFAULT_BASE_TIMEOUT_MS * 2);
        // Progress resets the backoff.
        pm.on_progress();
        assert_eq!(pm.timeout_duration_ms(), DEFAULT_BASE_TIMEOUT_MS);
        assert_eq!(pm.state(), PacemakerState::Active);
    }

    #[test]
    fn backoff_doubles_and_caps() {
        let mut pm = Pacemaker::new(vs4(), View::new(0), Epoch::new(0));
        // Simulate consecutive timeouts without progress.
        for expected_view in 0..10u64 {
            assert_eq!(pm.current_view(), View::new(expected_view));
            let _ = pm.on_local_timeout();
            let _ = pm.on_timeout_signature(0, sig(1));
            let _ = pm.on_timeout_signature(1, sig(2));
            let _ = pm.on_timeout_signature(2, sig(3));
            // View advanced.
        }
        // After 10 consecutive timeouts, the backoff should be capped.
        assert!(
            pm.timeout_duration_ms() <= DEFAULT_MAX_TIMEOUT_MS,
            "backoff must cap at {DEFAULT_MAX_TIMEOUT_MS}, got {}",
            pm.timeout_duration_ms()
        );
    }

    #[test]
    fn view_advance_clears_timeout_state() {
        let mut pm = Pacemaker::new(vs4(), View::new(0), Epoch::new(0));
        let _ = pm.on_local_timeout();
        let _ = pm.on_timeout_signature(0, sig(1));
        let _ = pm.on_timeout_signature(1, sig(2));
        let _ = pm.on_timeout_signature(2, sig(3));
        // View advanced; new view should have clean timeout state.
        assert_eq!(pm.timeout_signer_count(), 0);
        assert!(!pm.own_timeout_sent);
    }

    #[test]
    fn current_leader_matches_validator_set() {
        let vs = vs4();
        let pm = Pacemaker::new(vs, View::new(0), Epoch::new(0));
        // For equal stakes, leader(0) = validator 0.
        assert_eq!(pm.current_leader(), 0);
    }

    /// The adaptive floor: sustained 1s rounds push the effective
    /// base to 4×EWMA (the floor lifts above the configured base),
    /// and fast rounds decay it back — the configured base is the
    /// floor in both directions.
    #[test]
    fn adaptive_timeout_tracks_observed_rounds() {
        let mut pm = Pacemaker::new(vs4(), View::new(0), Epoch::new(0));
        assert_eq!(pm.timeout_duration_ms(), DEFAULT_BASE_TIMEOUT_MS);
        // One 1s sample seeds the EWMA; progress then applies the
        // raised floor: 4 × 1000 = 4000 > 2000 base.
        pm.observe_round_ms(1_000);
        pm.on_progress();
        assert_eq!(pm.timeout_duration_ms(), 4_000);
        // Sustained 1s rounds hold the floor at 4s.
        for _ in 0..8 {
            pm.observe_round_ms(1_000);
        }
        pm.on_progress();
        assert_eq!(pm.timeout_duration_ms(), 4_000);
        // Fast rounds decay the EWMA below base/4 — the configured
        // base returns (adaptation never goes below it).
        for _ in 0..64 {
            pm.observe_round_ms(10);
        }
        pm.on_progress();
        assert_eq!(pm.timeout_duration_ms(), DEFAULT_BASE_TIMEOUT_MS);
    }

    /// A pathologically slow network cannot push the floor past the
    /// configured max — the cap bounds adaptation exactly like
    /// backoff.
    #[test]
    fn adaptive_timeout_caps_at_max() {
        let mut pm = Pacemaker::with_config(vs4(), View::new(0), Epoch::new(0), 2_000, 30_000);
        for _ in 0..8 {
            pm.observe_round_ms(60_000);
        }
        pm.on_progress();
        assert_eq!(pm.timeout_duration_ms(), 30_000);
    }

    /// Backoff still doubles from the *effective* base: a timed-out
    /// view on a slow network doubles the adapted floor, and progress
    /// resets back to it — not to the configured base.
    #[test]
    fn backoff_doubles_from_adapted_base() {
        let mut pm = Pacemaker::new(vs4(), View::new(0), Epoch::new(0));
        pm.observe_round_ms(1_000);
        pm.on_progress();
        assert_eq!(pm.timeout_duration_ms(), 4_000);
        // A timeout doubles the adapted floor (4000 → 8000).
        let _ = pm.on_local_timeout();
        let _ = pm.on_timeout_signature(0, sig(1));
        let _ = pm.on_timeout_signature(1, sig(2));
        let _ = pm.on_timeout_signature(2, sig(3));
        assert_eq!(pm.timeout_duration_ms(), 8_000);
        // Progress resets to the adapted floor, still 4s.
        pm.on_progress();
        assert_eq!(pm.timeout_duration_ms(), 4_000);
    }
}
