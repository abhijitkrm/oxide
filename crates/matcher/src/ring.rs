//! Bounded single-producer/single-consumer ring buffer — the real
//! thing, not a channel wrapper (hft-audit F-03).
//!
//! Each request handler writes to its own ring; a single matcher
//! sequencer thread reads from all rings round-robin. The previous
//! implementation delegated to `crossbeam_channel::bounded` — an
//! MPMC channel whose per-send cost includes a slot-stamp CAS and a
//! deque-wide backoff path the SPSC contract never exercises. This
//! ring drops that machinery: the producer and consumer each own one
//! monotonically-advancing index, published with release stores and
//! read with acquire loads — one atomic store per push, one per pop,
//! no CAS loop anywhere.
//!
//! # Memory-ordering protocol
//!
//! - Producer: reads `head` (acquire), writes the slot payload, then
//!   publishes it with `tail.store(.., Release)`. The release store
//!   pairs with the consumer's acquire load of `tail`: any payload
//!   write sequenced before the store is visible to a consumer that
//!   observes the advanced tail.
//! - Consumer: symmetric — reads `tail` (acquire), reads the slot,
//!   publishes reclamation with `head.store(.., Release)`.
//! - Full iff `tail - head == capacity`; empty iff `tail == head`.
//!   Indices are monotonically increasing `usize`s masked into the
//!   slot array — no wraparound bookkeeping while `usize` can hold
//!   `u64::MAX` pushes (a 2^64-item ring is unreachable; practical
//!   capacities are ≤ 2^20).
//!
//! # Wakeup
//!
//! Producers signal the consumer through a [`Wakeup`] parked-flag
//! (sync consumers) or a `tokio::sync::Notify` (async consumers) —
//! see [`WakeTarget`]. The producer hot path pays ONE atomic swap in
//! the common case (`parked == false` → no notify needed); the
//! mutex/condvar is touched only when the consumer actually parked.
//!
//! # Push semantics
//!
//! `push` returns `Result<(), PushError<T>>`: on failure (ring full,
//! consumer gone, ring severed) the value is returned to the caller
//! so it can retry without data loss. Callers must NOT use
//! `take().expect()` patterns — the previous such pattern was a
//! production crash bug (the value was moved into `push`, dropped on
//! failure, and the next `take()` panicked on `None`).

use std::cell::UnsafeCell;
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::Duration;

/// One ring slot — an uninitialised cell the producer writes before
/// publishing `tail` and the consumer reads after observing it.
///
/// `UnsafeCell` is the arena primitive here: a fixed slab of slots
/// recycled by index arithmetic (production-rust §4 confines unsafe
/// to arenas — this IS the arena). See `Ring`'s SAFETY notes.
struct Slot<T>(UnsafeCell<MaybeUninit<T>>);

/// The shared ring body. Fields are split by owner across cache
/// lines so the producer's `tail` stores never invalidate the line
/// the consumer is polling (`head`), and vice versa — the classic
/// false-sharing split every SPSC queue needs (LMAX/Jctools shape).
///
/// SAFETY invariant (why `Sync` below is sound):
/// - SPSC by construction: the type system keeps `SpscSender`
///   un-`Clone` and the `RingMatcher` lease serializes the human
///   producers. `push` writes only slots in `[head, tail)`, `pop`
///   only slots in `[head, tail)` from the consumer's view — the two
///   index domains are disjoint at every instant, so no two threads
///   can touch the same slot concurrently.
/// - Hand-off is via the release/acquire pair on `tail`/`head`
///   described in the module docs.
struct Ring<T> {
    /// The slab — capacity slots, `MaybeUninit` until written.
    slots: Box<[Slot<T>]>,
    /// `capacity - 1`; slots index as `counter & mask` (capacity is
    /// a power of two — asserted at construction).
    mask: usize,
    /// Next position the producer writes. Written by producer,
    /// read by consumer. Own cache line.
    tail: CacheLine<AtomicUsize>,
    /// Next position the consumer reads. Written by consumer, read
    /// by producer. Own cache line — never shares with `tail`.
    head: CacheLine<AtomicUsize>,
    /// Consumer liveness: `false` once the receiver half drops.
    /// Read by `push` (acquire) to reject into `Disconnected`.
    consumer_alive: CacheLine<AtomicBool>,
    /// Producer liveness: `false` once the sender half drops. The
    /// consumer reads it to distinguish "empty" from "dead".
    producer_alive: CacheLine<AtomicBool>,
    /// Sever flag (hft-audit F-04): the producer may mark the ring
    /// dead when a consumer stops draining — the consumer's next
    /// liveness probe sees `false` and tears down instead of
    /// holding a lease forever. Producer-written, consumer-read.
    severed: AtomicBool,
    /// Signaled once per successful `pop` — a producer retrying on
    /// `Full` parks on this instead of `yield_now` polling
    /// (hft-audit F-15). Lives on the ring body so both halves can
    /// reach it; the producer only ever awaits it, the consumer only
    /// ever fires it.
    space: tokio::sync::Notify,
}

// SAFETY: `Ring` is shared between exactly one producer and one
// consumer. Slot access is exclusive per the index-domain argument
// above; the atomics carry the cross-thread publication. `T: Send`
// because values cross the thread boundary. (Justification: memory
// arena — production-rust §4.)
#[allow(unsafe_code)]
unsafe impl<T: Send> Send for Ring<T> {}
// SAFETY: as above — `&Ring` is only ever used through the SPSC
// protocol; no `&mut`-level aliasing of a slot is possible.
#[allow(unsafe_code)]
unsafe impl<T: Send> Sync for Ring<T> {}

impl<T> Drop for Ring<T> {
    /// Drain initialized slots — `[head, tail)` is exactly the set
    /// of live values; everything outside was never written or was
    /// already taken.
    fn drop(&mut self) {
        let mut idx = self.head.value.load(Ordering::Relaxed);
        let end = self.tail.value.load(Ordering::Relaxed);
        while idx != end {
            let slot = &self.slots[idx & self.mask];
            // SAFETY: `idx` is in `[head, tail)` — the slot was
            // initialized by a completed `push` and never consumed.
            #[allow(unsafe_code)]
            unsafe {
                slot.0.get().cast::<T>().drop_in_place();
            };
            idx += 1;
        }
    }
}

/// A cache-line-aligned wrapper for one atomically-owned value —
/// the false-sharing barrier between producer-owned and
/// consumer-owned counters. `#[repr(align(64))]` pads to the
/// x86/ARM cache-line width.
#[repr(align(64))]
struct CacheLine<T> {
    value: T,
}

impl<T> CacheLine<T> {
    fn new(v: T) -> Self {
        Self { value: v }
    }
}

/// How a successful `push` wakes the ring's consumer.
///
/// The matcher's two ring directions need different waiters: the
/// sequencer thread sleeps on a [`Wakeup`] condvar (blocking sleep
/// is legal on a dedicated thread), while a lease-holding request
/// handler is a tokio task that MUST NOT block — it parks on a
/// `Notify` instead.
#[derive(Clone)]
enum WakeTarget {
    /// Sync consumer — the sequencer's shared parked-flag.
    Sync(Arc<Wakeup>),
    /// Async consumer — a per-ring `Notify` the task awaits.
    Async(Arc<tokio::sync::Notify>),
    /// No consumer wakeup (standalone rings in tests).
    Silent,
}

/// Shared wakeup latch for a blocking consumer: the producer calls
/// [`Wakeup::signal`] after a successful push; the consumer calls
/// [`Wakeup::wait_for_work`] when all rings are idle.
///
/// # Parked-flag protocol (no lost wakeups, no hot-path mutex)
///
/// `signal()` is a single `parked.swap(false)` — free when nobody
/// sleeps, and it only takes the mutex when the swap observes
/// `parked == true`. `wait_for_work` announces `parked = true`
/// BEFORE re-checking for work, so a signal that lands between the
/// announcement and the lock is observed by the in-lock `parked`
/// re-check — the notify is never lost because the signaler holds
/// the mutex across `notify_one`, forcing the would-be-sleeper to
/// see the cleared flag before it can enter `wait_timeout`.
///
/// All rings in a [`RingMatcher`](crate::RingMatcher) share one
/// `Wakeup` so a push on any ring wakes the sequencer.
pub struct Wakeup {
    /// `true` while the consumer has announced intent to sleep and
    /// has not yet been woken or retracted.
    parked: AtomicBool,
    /// Guards the sleep/wake hand-off: signalers take it AFTER
    /// observing `parked == true` so their `notify_one` cannot slip
    /// between a waiter's flag check and its `wait_timeout` call.
    sleep: Mutex<()>,
    /// The actual sleep object.
    cond: Condvar,
}

impl Wakeup {
    /// Create a new wakeup signal in the "consumer awake" state.
    #[must_use]
    pub fn new() -> Self {
        Self { parked: AtomicBool::new(false), sleep: Mutex::new(()), cond: Condvar::new() }
    }

    /// Signal that work is available. One atomic swap when the
    /// consumer is running (the hot path); mutex+notify only when it
    /// actually parked.
    ///
    /// # Panics
    ///
    /// Never: a poisoned sleep mutex is recovered via `into_inner`
    /// (production-rust §8) — a dead waiter thread must not cascade
    /// a panic into every producer.
    #[inline]
    pub fn signal(&self) {
        // AcqRel: acquire so a true-swap observes the consumer's
        // announcement (and its subsequent sleeps); release so a
        // consumer observing the false-swap sees our just-pushed
        // ring entries (the producer wrote them before calling).
        if self.parked.swap(false, Ordering::AcqRel) {
            // The consumer is (or is about to be) inside `wait_for_work`'s
            // critical section. Holding the mutex across notify_one
            // forces the consumer to observe `parked == false` before
            // it may sleep — the notify cannot be missed.
            let _guard = self.sleep.lock().unwrap_or_else(PoisonError::into_inner);
            self.cond.notify_one();
        }
    }

    /// Block until `has_work` reports true or `timeout` elapses.
    /// `has_work` is the consumer's own "any ring non-empty" probe —
    /// passing it in lets the announce-then-recheck ordering fall out
    /// naturally without the wakeup knowing anything about rings.
    ///
    /// Returns `true` when the caller should poll rings (work seen or
    /// a wakeup fired), `false` on a genuine idle timeout.
    ///
    /// # Panics
    ///
    /// Never: poisoned mutexes are recovered via `into_inner`
    /// (production-rust §8).
    pub fn wait_for_work(&self, timeout: Duration, has_work: impl Fn() -> bool) -> bool {
        loop {
            // SeqCst: the announcement must be globally ordered before
            // the `has_work` probe — a producer whose `swap` precedes
            // this store in the total order must have its push visible
            // to the probe (pairing release/acquire on the ring itself
            // plus the swap's release edge makes that chain hold).
            self.parked.store(true, Ordering::SeqCst);
            if has_work() {
                self.parked.store(false, Ordering::SeqCst);
                return true;
            }
            {
                let guard = self.sleep.lock().unwrap_or_else(PoisonError::into_inner);
                // A signal may have fired between the announcement and
                // this lock — it cleared `parked`, so we must not sleep.
                if !self.parked.load(Ordering::Acquire) {
                    continue;
                }
                let (guard, result) = self
                    .cond
                    .wait_timeout(guard, timeout)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                drop(guard);
                if result.timed_out() {
                    // Retract the announcement, then take one final
                    // probe — a push that raced the timeout must not
                    // strand work for another timeout window.
                    self.parked.store(false, Ordering::SeqCst);
                    return has_work();
                }
                // Signaled (or spuriously woken): loop around and
                // re-probe — `has_work` is the only source of truth.
            }
        }
    }
}

impl Default for Wakeup {
    fn default() -> Self {
        Self::new()
    }
}

/// How long the sequencer keeps busy-polling its rings after the last
/// unit of work before it parks on the [`Wakeup`] condvar
/// (hft-audit-2 M-2).
///
/// Why spin at all: parking costs the NEXT order a `mutex +
/// notify_one` on the producer, a futex wake, and a scheduler/C-state
/// exit on the sequencer — 15–100 µs measured on the x86 target box
/// against a ~0.5 µs match. Order flow arrives in bursts, so most
/// inter-arrival gaps at sub-saturation load are far shorter than
/// this window and the next order lands on a hot, running thread.
///
/// Why 200 µs: the audit's recommended band is 100–300 µs. It is
/// long enough to cover a client's ack→next-order round trip on
/// loopback (~20–60 µs) with margin, and short enough that an idle
/// venue burns at most 200 µs of one core per burst before it
/// sleeps. Raising it trades CPU for tail latency on sparser flow;
/// lowering it toward 0 converges on [`SequencerIdle::Park`].
pub const SEQUENCER_SPIN_BUDGET: Duration = Duration::from_micros(200);

/// Empty passes between clock reads while spinning. A pass over the
/// default 256 rings is a few hundred ns, so 16 passes gives ~5–15 µs
/// budget resolution while keeping `Instant::now` (a vDSO call) out of
/// most of the spin. Larger values overshoot the budget more; smaller
/// values spend more of the spin reading the clock.
const SPIN_PASSES_PER_CLOCK_CHECK: u32 = 16;

/// What the sequencer does when a full pass over its rings finds no
/// work (`--sequencer-idle` on `oxide-matcher`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SequencerIdle {
    /// Busy-poll for [`SEQUENCER_SPIN_BUDGET`], then park. The
    /// default: a burst's follow-on orders reach a running thread
    /// instead of paying a futex wake each (hft-audit-2 M-2).
    #[default]
    Spin,
    /// Park on the first empty pass — the pre-M-2 behaviour. For
    /// shared hosts and laptops where a briefly burning core matters
    /// more than wake latency.
    Park,
}

/// A `--sequencer-idle` value that is neither `spin` nor `park`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownSequencerIdle(pub String);

impl std::fmt::Display for UnknownSequencerIdle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "unknown sequencer idle policy '{}' (use spin or park)", self.0)
    }
}

impl std::error::Error for UnknownSequencerIdle {}

impl std::str::FromStr for SequencerIdle {
    type Err = UnknownSequencerIdle;

    /// Parses the CLI spelling: `spin` or `park`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "spin" => Ok(Self::Spin),
            "park" => Ok(Self::Park),
            other => Err(UnknownSequencerIdle(other.to_string())),
        }
    }
}

/// The sequencer's spin-then-park bookkeeping. Call [`on_work`]
/// after a pass that did work and [`should_park`] after one that did
/// not. It reads the clock only once every
/// [`SPIN_PASSES_PER_CLOCK_CHECK`] empty passes, and never while work
/// keeps arriving, so a busy sequencer pays nothing for it.
///
/// [`on_work`]: IdleSpinner::on_work
/// [`should_park`]: IdleSpinner::should_park
#[derive(Debug)]
pub(crate) struct IdleSpinner {
    /// Spin window; `None` = park immediately ([`SequencerIdle::Park`]).
    budget: Option<Duration>,
    /// When the current run of empty passes began; `None` while busy.
    idle_since: Option<std::time::Instant>,
    /// Empty passes since the last clock read.
    passes: u32,
}

impl IdleSpinner {
    /// A spinner for `policy`, using the production budget.
    pub(crate) fn new(policy: SequencerIdle) -> Self {
        Self::with_budget(match policy {
            SequencerIdle::Spin => Some(SEQUENCER_SPIN_BUDGET),
            SequencerIdle::Park => None,
        })
    }

    /// A spinner with an explicit window (tests drive edge budgets).
    pub(crate) fn with_budget(budget: Option<Duration>) -> Self {
        Self { budget, idle_since: None, passes: 0 }
    }

    /// The last pass did work (or the thread just woke): the next
    /// empty pass starts a fresh spin window.
    #[inline]
    pub(crate) fn on_work(&mut self) {
        self.idle_since = None;
        self.passes = 0;
    }

    /// The last pass found nothing. Returns `true` when the spin
    /// window is used up and the caller should park; otherwise issues
    /// a CPU spin hint and returns `false` so the caller polls again.
    #[inline]
    pub(crate) fn should_park(&mut self) -> bool {
        let Some(budget) = self.budget else {
            return true;
        };
        let Some(since) = self.idle_since else {
            self.idle_since = Some(std::time::Instant::now());
            self.passes = 0;
            std::hint::spin_loop();
            return false;
        };
        self.passes += 1;
        if self.passes >= SPIN_PASSES_PER_CLOCK_CHECK {
            self.passes = 0;
            if since.elapsed() >= budget {
                return true;
            }
        }
        std::hint::spin_loop();
        false
    }
}

/// Why a `push` failed. The value is always returned to the caller
/// so it can retry without data loss.
#[derive(Debug)]
pub enum PushError<T> {
    /// Ring is at capacity. Retry after the consumer drains some items.
    Full(T),
    /// Consumer half has been dropped or severed. Retrying is futile —
    /// the matcher worker or client connection is gone.
    Disconnected(T),
}

/// The producer half of an SPSC ring.
///
/// `push` is non-blocking — it returns `Err(Full)` when the ring is
/// full (the consumer must catch up first). This provides
/// backpressure without blocking the producer.
///
/// Deliberately NOT `Clone`: forbidding clones keeps the
/// single-producer guarantee enforceable. Shared use is serialized
/// by the [`RingMatcher`](crate::RingMatcher) ring lease; a
/// `debug_assertions` in-flight guard makes two producers inside
/// `push` simultaneously panic in debug/test builds rather than
/// silently corrupt the index domain (concurrent `push` is UB — two
/// writers race the same slot cell).
pub struct SpscSender<T> {
    /// The shared ring body.
    ring: Arc<Ring<T>>,
    /// Capacity in items (slots); `push` is `Full` at this depth.
    capacity: usize,
    /// What a successful push signals.
    wake: WakeTarget,
    /// Debug-build guard flag: held for the duration of each `push`'s
    /// producer-critical section — a concurrent `push` overlapping it
    /// trips the assert (single-producer violation).
    #[cfg(debug_assertions)]
    in_push: Arc<AtomicBool>,
}

/// The consumer half of an SPSC ring.
///
/// `pop` is non-blocking — it returns `None` when the ring is empty.
/// A successful pop fires the ring's `space` notify so an async
/// producer retrying on `Full` wakes without polling.
///
/// Deliberately NOT `Clone`: a cloned consumer can race the real
/// one and steal responses addressed to another requester.
pub struct SpscReceiver<T> {
    /// The shared ring body.
    ring: Arc<Ring<T>>,
    /// Signaled by each producer `push` when [`WakeTarget::Async`] —
    /// the consumer task awaits it between pops.
    data: Arc<tokio::sync::Notify>,
}

/// Create an SPSC ring pair: (sender, receiver). Pushes do not wake
/// a consumer — standalone rings for tests and unpaired use.
///
/// # Panics
/// Panics unless `capacity` is a power of two (the mask indexing
/// requires it).
#[must_use]
pub fn spsc_ring<T>(capacity: usize) -> (SpscSender<T>, SpscReceiver<T>) {
    spsc_ring_inner(capacity, WakeTarget::Silent)
}

/// Create an SPSC ring pair whose pushes signal `wakeup` — the
/// sequencer-facing direction. All order rings of a
/// [`RingMatcher`](crate::RingMatcher) share one `Wakeup`.
///
/// # Panics
/// Panics unless `capacity` is a power of two.
#[must_use]
pub fn spsc_ring_with_wakeup<T>(
    capacity: usize,
    wakeup: Arc<Wakeup>,
) -> (SpscSender<T>, SpscReceiver<T>) {
    spsc_ring_inner(capacity, WakeTarget::Sync(wakeup))
}

/// Create an SPSC ring pair whose pushes signal `notify` — the
/// task-facing direction (response rings): the consumer is a tokio
/// task that awaits the same `Notify` between pops.
///
/// # Panics
/// Panics unless `capacity` is a power of two.
#[must_use]
pub fn spsc_ring_with_notify<T>(
    capacity: usize,
    notify: Arc<tokio::sync::Notify>,
) -> (SpscSender<T>, SpscReceiver<T>) {
    spsc_ring_inner(capacity, WakeTarget::Async(notify))
}

fn spsc_ring_inner<T>(capacity: usize, wake: WakeTarget) -> (SpscSender<T>, SpscReceiver<T>) {
    assert!(capacity.is_power_of_two(), "ring capacity must be a power of two");
    let data = match &wake {
        WakeTarget::Async(n) => Arc::clone(n),
        _ => Arc::new(tokio::sync::Notify::new()),
    };
    let ring = Arc::new(Ring {
        slots: (0..capacity).map(|_| Slot(UnsafeCell::new(MaybeUninit::uninit()))).collect(),
        mask: capacity - 1,
        tail: CacheLine::new(AtomicUsize::new(0)),
        head: CacheLine::new(AtomicUsize::new(0)),
        consumer_alive: CacheLine::new(AtomicBool::new(true)),
        producer_alive: CacheLine::new(AtomicBool::new(true)),
        severed: AtomicBool::new(false),
        space: tokio::sync::Notify::new(),
    });
    (
        SpscSender {
            ring: Arc::clone(&ring),
            capacity,
            wake,
            #[cfg(debug_assertions)]
            in_push: Arc::new(AtomicBool::new(false)),
        },
        SpscReceiver { ring, data },
    )
}

impl<T> SpscSender<T> {
    /// Push a value into the ring.
    ///
    /// One atomic load (`head`), one slot write, one release store
    /// (`tail`), one swap on the wakeup — no CAS loop, no syscall.
    /// On `Err` the value is handed back for retry without loss.
    ///
    /// # Errors
    /// `PushError::Full` when at capacity, `PushError::Disconnected`
    /// when the consumer has been dropped or the ring severed.
    #[inline]
    pub fn push(&self, value: T) -> Result<(), PushError<T>> {
        // SPSC contract check (debug/test only): the guard covers the
        // write-critical-section below — two threads inside `push` at
        // once is a lease violation and would race the slot cell.
        #[cfg(debug_assertions)]
        let _push_guard = {
            // Declared before the statement it serves — items exist
            // for the whole block, but listing them first keeps the
            // guard readable (clippy::items_after_statements).
            struct Guard<'a>(&'a AtomicBool);
            impl Drop for Guard<'_> {
                fn drop(&mut self) {
                    self.0.store(false, Ordering::Release);
                }
            }
            debug_assert!(
                !self.in_push.swap(true, Ordering::AcqRel),
                "SpscSender used by two producers at once — a ring lease violation"
            );
            Guard(&self.in_push)
        };
        let ring = &*self.ring;
        let tail = ring.tail.value.load(Ordering::Relaxed);
        // Acquire: observe the consumer's reclamation stores.
        let head = ring.head.value.load(Ordering::Acquire);
        if tail - head == self.capacity {
            return Err(PushError::Full(value));
        }
        if !ring.consumer_alive.value.load(Ordering::Acquire)
            || ring.severed.load(Ordering::Acquire)
        {
            return Err(PushError::Disconnected(value));
        }
        // SAFETY: the producer owns `[head, tail)`; this slot is
        // below tail, uninitialised (never written or already
        // consumed — the consumer only reads `< tail`), and no other
        // thread can be writing it (single producer).
        #[allow(unsafe_code)]
        unsafe {
            ring.slots[tail & ring.mask].0.get().cast::<T>().write(value);
        }
        // Release: publishes the slot write to any consumer that
        // observes the new tail.
        ring.tail.value.store(tail + 1, Ordering::Release);
        match &self.wake {
            WakeTarget::Sync(w) => w.signal(),
            WakeTarget::Async(n) => n.notify_one(),
            WakeTarget::Silent => {}
        }
        Ok(())
    }

    /// Mark the ring dead toward its consumer: the next
    /// `producer_gone`/`is_closed` probe on the receiver reports the
    /// loss and the client bails instead of holding its lease while
    /// a response can never arrive. The sequencer uses this when a
    /// response push is refused past its patience bound — strictly a
    /// liveness signal; no buffered item is harmed.
    ///
    /// This is the F-04 escape: a client that stops draining no
    /// longer deadlocks the sequencer's response path.
    pub fn sever(&self) {
        self.ring.severed.store(true, Ordering::Release);
        // Wake the consumer so it observes the flag promptly instead
        // of timing out.
        match &self.wake {
            WakeTarget::Sync(w) => w.signal(),
            WakeTarget::Async(n) => n.notify_one(),
            WakeTarget::Silent => {}
        }
    }

    /// The `Notify` this producer awaits when `push` reports `Full` —
    /// signalled once per successful consumer `pop` (hft-audit F-15:
    /// replaces `yield_now` polling). Use the register-then-recheck
    /// pattern: `notified()` + `enable()`, re-attempt `push`, then
    /// `await` only if still full.
    #[must_use]
    pub fn space_notify(&self) -> &tokio::sync::Notify {
        &self.ring.space
    }

    /// Number of items in flight (an instantaneous, racy estimate —
    /// the consumer moves `head` concurrently).
    #[inline]
    pub fn len(&self) -> usize {
        let tail = self.ring.tail.value.load(Ordering::Relaxed);
        let head = self.ring.head.value.load(Ordering::Acquire);
        tail - head
    }

    /// Is the ring empty?
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Is the ring full?
    #[inline]
    pub fn is_full(&self) -> bool {
        self.len() >= self.capacity
    }
}

impl<T> Drop for SpscSender<T> {
    fn drop(&mut self) {
        self.ring.producer_alive.value.store(false, Ordering::Release);
        // Wake the consumer one last time so it observes the
        // liveness flag rather than sitting out its timeout.
        match &self.wake {
            WakeTarget::Sync(w) => w.signal(),
            WakeTarget::Async(n) => n.notify_one(),
            WakeTarget::Silent => {}
        }
    }
}

impl<T> SpscReceiver<T> {
    /// Pop a value from the ring. Returns `None` if empty (probe
    /// `producer_gone`/`severed` to distinguish idle from dead).
    ///
    /// One acquire load (`tail`), one slot read, one release store
    /// (`head`) — plus a `Notify` store that is a single atomic in
    /// the no-waiter common case.
    #[inline]
    pub fn pop(&self) -> Option<T> {
        let ring = &*self.ring;
        let head = ring.head.value.load(Ordering::Relaxed);
        let tail = ring.tail.value.load(Ordering::Acquire);
        if head == tail {
            return None;
        }
        // SAFETY: the consumer owns reads below `tail`; this slot was
        // initialized by the producer's release-published write, and
        // the consumer is the only reader (single consumer).
        #[allow(unsafe_code)]
        let value = unsafe { ring.slots[head & ring.mask].0.get().cast::<T>().read() };
        // Release: publishes slot reclamation to the producer's
        // acquire load of `head`.
        ring.head.value.store(head + 1, Ordering::Release);
        // Wake a producer parked on space. Single atomic store when
        // nobody waits — the no-waiter case dominates (consumers are
        // normally behind, not ahead, of producers).
        self.ring.space.notify_one();
        Some(value)
    }

    /// Pop, busy-polling for up to `budget` before giving up — the
    /// "brief spin" half of spin-then-park for an async consumer
    /// (hft-audit-2 M-2). A response that lands within the window is
    /// taken without the `Notify` round trip through the tokio
    /// scheduler (a remote wake when the consumer task has already
    /// yielded its worker).
    ///
    /// Returns `None` once the budget is spent or the producer is
    /// gone; the caller then falls back to its `Notify` wait, which
    /// stays the only correctness path. The clock is read every
    /// [`SPIN_PASSES_PER_CLOCK_CHECK`] polls, so the window can
    /// overshoot by a few hundred ns. Callers on an async executor
    /// must keep `budget` short (tens of µs): spinning holds the
    /// worker thread.
    #[inline]
    pub fn pop_spin(&self, budget: Duration) -> Option<T> {
        if let Some(v) = self.pop() {
            return Some(v);
        }
        if budget.is_zero() {
            return None;
        }
        let start = std::time::Instant::now();
        let mut polls = 0u32;
        loop {
            std::hint::spin_loop();
            if let Some(v) = self.pop() {
                return Some(v);
            }
            polls += 1;
            if polls >= SPIN_PASSES_PER_CLOCK_CHECK {
                polls = 0;
                if self.producer_gone() || start.elapsed() >= budget {
                    // One last probe: a value published just before
                    // the producer dropped is still deliverable.
                    return self.pop();
                }
            }
        }
    }

    /// The `Notify` signalled by producer pushes when this ring was
    /// built with [`spsc_ring_with_notify`] — the consumer task
    /// awaits it instead of `yield_now` polling (hft-audit F-15).
    /// For sync-wakeup rings this is an internal no-op handle.
    #[must_use]
    pub fn data_notify(&self) -> &Arc<tokio::sync::Notify> {
        &self.data
    }

    /// `true` once the producer half has dropped or called `sever`
    /// — an empty pop with this set means no value can ever arrive;
    /// the caller must bail rather than hold a lease forever.
    #[inline]
    #[must_use]
    pub fn producer_gone(&self) -> bool {
        !self.ring.producer_alive.value.load(Ordering::Acquire)
            || self.ring.severed.load(Ordering::Acquire)
    }

    /// Number of items in flight (instantaneous estimate — the
    /// producer moves `tail` concurrently).
    #[inline]
    pub fn len(&self) -> usize {
        let head = self.ring.head.value.load(Ordering::Relaxed);
        let tail = self.ring.tail.value.load(Ordering::Acquire);
        tail - head
    }

    /// Is the ring empty?
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<T> Drop for SpscReceiver<T> {
    fn drop(&mut self) {
        self.ring.consumer_alive.value.store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Instant;

    #[test]
    fn push_pop_single_threaded() {
        let (tx, rx) = spsc_ring::<u64>(8);
        assert!(rx.is_empty());
        assert!(tx.push(42).is_ok());
        assert_eq!(rx.len(), 1);
        assert_eq!(rx.pop(), Some(42));
        assert!(rx.is_empty());
    }

    #[test]
    fn ring_full() {
        let (tx, rx) = spsc_ring::<u64>(4);
        for i in 0..4 {
            assert!(tx.push(i).is_ok());
        }
        assert!(tx.is_full());
        // Full push returns the value back (no data loss).
        assert!(matches!(tx.push(5), Err(PushError::Full(5))));
        assert_eq!(rx.pop(), Some(0));
        assert!(tx.push(5).is_ok()); // Now fits.
    }

    #[test]
    fn push_returns_value_on_full() {
        // Regression: previously `push` returned `bool` and DROPPED the
        // value on failure, causing `take().expect()` panics in callers.
        let (tx, _rx) = spsc_ring::<u64>(2);
        assert!(tx.push(1).is_ok());
        assert!(tx.push(2).is_ok());
        // Third push must return the value, not drop it.
        let err = tx.push(3);
        assert!(matches!(err, Err(PushError::Full(3))));
    }

    #[test]
    fn disconnected_returns_value() {
        let (tx, rx) = spsc_ring::<u64>(4);
        drop(rx); // Consumer gone.
        let err = tx.push(42);
        assert!(matches!(err, Err(PushError::Disconnected(42))));
    }

    #[test]
    fn severed_ring_reports_dead_producer_and_rejects_pushes() {
        // F-04 regression: `sever` must (a) make the consumer's
        // liveness probe report dead and (b) bounce subsequent pushes.
        let (tx, rx) = spsc_ring::<u64>(4);
        tx.sever();
        assert!(rx.producer_gone());
        assert!(matches!(tx.push(1), Err(PushError::Disconnected(1))));
    }

    #[test]
    fn sender_drop_reports_gone_to_consumer() {
        let (tx, rx) = spsc_ring::<u64>(4);
        tx.push(7).ok();
        drop(tx);
        assert!(rx.producer_gone());
        // Buffered items are still delivered — gone is not empty-loss.
        assert_eq!(rx.pop(), Some(7));
        assert!(rx.pop().is_none());
    }

    #[test]
    fn spsc_concurrent() {
        let (tx, rx) = spsc_ring::<u64>(1024);

        let producer = thread::spawn(move || {
            for i in 0..10_000u64 {
                let mut val = i;
                while let Err(PushError::Full(returned)) = tx.push(val) {
                    val = returned;
                    std::hint::spin_loop();
                }
            }
        });

        let consumer = thread::spawn(move || {
            let mut received = 0u64;
            while received < 10_000 {
                if let Some(v) = rx.pop() {
                    assert_eq!(v, received);
                    received += 1;
                }
            }
            received
        });

        producer.join().unwrap();
        assert_eq!(consumer.join().unwrap(), 10_000);
    }

    #[test]
    fn wakeup_signal_then_wait_returns_immediately() {
        // A signal fired before wait must not be lost — the parked
        // flag carries it into the waiter's first probe.
        let w = Wakeup::new();
        w.signal();
        // has_work=true mirrors "ring non-empty" — the wait must
        // observe the not-parked state and exit promptly.
        let saw = w.wait_for_work(Duration::from_millis(50), || true);
        assert!(saw);
    }

    #[test]
    fn wakeup_blocks_then_wakes_on_signal() {
        // The producer signals while the consumer sleeps — a bounded
        // wait must wake well under the timeout.
        let w = Arc::new(Wakeup::new());
        let w2 = Arc::clone(&w);
        // Shared "work appeared" flag — stands in for a ring write.
        let work = Arc::new(AtomicBool::new(false));
        let work2 = Arc::clone(&work);
        let sleeper = thread::spawn(move || {
            let work = work2;
            w2.wait_for_work(Duration::from_secs(30), || work.load(Ordering::Acquire))
        });
        // Give the sleeper a real chance to park before signalling —
        // the parked-flag protocol makes the signal wait-proof either
        // way, so this is about exercising the notify path, not a
        // correctness race.
        thread::sleep(Duration::from_millis(20));
        work.store(true, Ordering::Release);
        let t0 = Instant::now();
        w.signal();
        sleeper.join().unwrap();
        assert!(t0.elapsed() < Duration::from_secs(5), "wakeup latency must be near-instant");
    }

    #[test]
    fn wakeup_race_signal_before_park_does_not_sleep() {
        // Signal racing just ahead of the park announcement must be
        // caught by the in-lock re-check — the waiter sees
        // `parked == false` and loops instead of sleeping forever.
        let w = Arc::new(Wakeup::new());
        let w2 = Arc::clone(&w);
        let handle = thread::spawn(move || {
            // has_work flips true on the first probe — the wait must
            // exit on the recheck, not on the 30s timeout.
            w2.wait_for_work(Duration::from_secs(30), || true)
        });
        w.signal();
        assert!(handle.join().unwrap());
    }

    #[test]
    fn idle_spinner_park_policy_parks_on_first_empty_pass() {
        // `SequencerIdle::Park` is the pre-M-2 behaviour: no spin.
        let mut s = IdleSpinner::new(SequencerIdle::Park);
        assert!(s.should_park());
    }

    #[test]
    fn idle_spinner_spins_until_budget_then_parks() {
        // A window far longer than the test spins for: never parks
        // within a bounded number of passes.
        let mut long = IdleSpinner::with_budget(Some(Duration::from_secs(3600)));
        for _ in 0..10 * SPIN_PASSES_PER_CLOCK_CHECK {
            assert!(!long.should_park(), "must keep spinning inside the window");
        }
        // A zero window parks at the first clock check after the run
        // of empty passes starts, never on the very first pass.
        let mut zero = IdleSpinner::with_budget(Some(Duration::ZERO));
        assert!(!zero.should_park(), "first empty pass only opens the window");
        let parked_after = (1..=SPIN_PASSES_PER_CLOCK_CHECK).find(|_| zero.should_park());
        assert_eq!(parked_after, Some(SPIN_PASSES_PER_CLOCK_CHECK));
    }

    #[test]
    fn idle_spinner_work_resets_the_window() {
        // Work mid-spin must restart the window, or a steady trickle
        // of orders would eventually park between every one.
        let mut s = IdleSpinner::with_budget(Some(Duration::ZERO));
        assert!(!s.should_park());
        for _ in 1..SPIN_PASSES_PER_CLOCK_CHECK {
            assert!(!s.should_park());
        }
        s.on_work();
        assert!(!s.should_park(), "a fresh window never parks on its first pass");
    }

    #[test]
    fn sequencer_idle_parses_cli_spellings() {
        assert_eq!("spin".parse::<SequencerIdle>(), Ok(SequencerIdle::Spin));
        assert_eq!("park".parse::<SequencerIdle>(), Ok(SequencerIdle::Park));
        assert!("busy".parse::<SequencerIdle>().is_err());
        assert_eq!(SequencerIdle::default(), SequencerIdle::Spin);
    }

    #[test]
    fn pop_spin_returns_value_pushed_during_the_spin() {
        let (tx, rx) = spsc_ring::<u64>(4);
        let producer = thread::spawn(move || {
            thread::sleep(Duration::from_millis(5));
            tx.push(9).ok();
            tx
        });
        // Generous window: the value must be taken by the spin, not
        // left for a Notify wait.
        assert_eq!(rx.pop_spin(Duration::from_secs(30)), Some(9));
        drop(producer.join().unwrap());
    }

    #[test]
    fn pop_spin_gives_up_on_empty_ring_and_dead_producer() {
        let (tx, rx) = spsc_ring::<u64>(4);
        assert_eq!(rx.pop_spin(Duration::ZERO), None);
        assert_eq!(rx.pop_spin(Duration::from_micros(50)), None);
        // A dead producer ends the spin early even with a huge budget
        // — but a value it published first is still delivered.
        tx.push(3).ok();
        drop(tx);
        assert_eq!(rx.pop_spin(Duration::from_secs(3600)), Some(3));
        let t0 = Instant::now();
        assert_eq!(rx.pop_spin(Duration::from_secs(3600)), None);
        assert!(t0.elapsed() < Duration::from_secs(5), "dead producer must end the spin");
    }

    #[test]
    fn drop_drains_unconsumed_slots() {
        // SAFETY-invariant guard: dropping a ring mid-flight must
        // destroy every written-but-unread value exactly once.
        use std::sync::atomic::AtomicUsize as AU;
        static DROPS: AU = AU::new(0);
        struct CountMe;
        impl Drop for CountMe {
            fn drop(&mut self) {
                DROPS.fetch_add(1, Ordering::Relaxed);
            }
        }
        let (tx, rx) = spsc_ring::<CountMe>(8);
        tx.push(CountMe).ok();
        tx.push(CountMe).ok();
        tx.push(CountMe).ok();
        assert!(rx.pop().is_some()); // consume one
        drop(rx);
        drop(tx); // ring body drops with the last half
        assert_eq!(DROPS.load(Ordering::Relaxed), 3);
    }
}
