//! Bounded SPSC ring buffer for the matching server.
//!
//! Each TCP connection writes to its own ring; a single matcher thread
//! reads from all rings round-robin. The underlying channel is
//! `crossbeam_channel::bounded`, a truly lock-free MPMC channel whose
//! `Receiver` is `Send + Sync` — no `Mutex` wrapper needed.
//!
//! # Design
//!
//! Uses `crossbeam_channel::bounded(capacity)` internally. This
//! provides:
//! - Lock-free sends and receives (atomics, no kernel futex on the
//!   fast path).
//! - Native bounded backpressure — `try_send` returns `Full` when the
//!   channel is at capacity.
//! - `Receiver<T>` is `Send + Sync` — no `Arc<Mutex<Receiver>>` needed,
//!   eliminating the uncontended-but-still-a-lock mutex from the
//!   previous `std::sync::mpsc` implementation.
//!
//! # Push semantics
//!
//! `push` returns `Result<(), T>`: on failure (ring full or consumer
//! disconnected), the value is returned to the caller so it can retry
//! without data loss. Callers must NOT use `take().expect()` patterns
//! — the previous such pattern was a production crash bug (the value
//! was moved into `push`, dropped on failure, and the next `take()`
//! panicked on `None`).

use std::sync::Arc;
use std::sync::{Condvar, Mutex};
use std::time::Duration;

use crossbeam_channel::{Receiver, Sender, bounded};

/// Shared wakeup signal for the ring consumer. The producer calls
/// [`Wakeup::signal`] after a successful push; the consumer calls
/// [`Wakeup::wait`] when all rings are idle, blocking until signalled
/// or the timeout elapses.
///
/// This replaces the previous `std::thread::yield_now()` busy-spin
/// that burned a full CPU core at 100% when the matcher was idle.
/// All rings in a [`RingMatcher`](crate::RingMatcher) share a single
/// `Wakeup` so that a push on any ring wakes the consumer.
pub struct Wakeup {
    /// Latched flag: set by `signal`, cleared by `wait`. Avoids a
    /// lost-wakeup race where `signal` fires between the consumer's
    /// "all rings empty" check and the `wait` call.
    flag: Mutex<bool>,
    cond: Condvar,
}

impl Wakeup {
    /// Create a new wakeup signal in the "no work" state.
    #[must_use]
    pub fn new() -> Self {
        Self { flag: Mutex::new(false), cond: Condvar::new() }
    }

    /// Signal that work is available. Wakes the consumer if it is
    /// blocked in [`wait`]. Safe to call from the producer (push)
    /// hot path — it is a single atomic store + `notify_one`.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned (a thread panicked
    /// while holding the lock).
    pub fn signal(&self) {
        let mut flag = self.flag.lock().expect("wakeup mutex poisoned");
        *flag = true;
        self.cond.notify_one();
    }

    /// Block until signalled or the timeout elapses. Returns
    /// immediately if work was already signalled (and clears the
    /// latch so the next `wait` blocks until a new `signal`).
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned (a thread panicked
    /// while holding the lock).
    pub fn wait(&self, timeout: Duration) {
        let mut flag = self.flag.lock().expect("wakeup mutex poisoned");
        if !*flag {
            let _ = self.cond.wait_timeout(flag, timeout).expect("wakeup mutex poisoned");
            flag = self.flag.lock().expect("wakeup mutex poisoned");
        }
        *flag = false;
    }
}

impl Default for Wakeup {
    fn default() -> Self {
        Self::new()
    }
}

/// Why a `push` failed. The value is always returned to the caller
/// so it can retry without data loss.
#[derive(Debug)]
pub enum PushError<T> {
    /// Ring is at capacity. Retry after the consumer drains some items.
    Full(T),
    /// Consumer half has been dropped. Retrying is futile — the
    /// matcher worker or client connection is gone.
    Disconnected(T),
}

/// The producer half of an SPSC ring. Pushes values to the consumer.
///
/// `push` is non-blocking — it returns `Err(Full)` when the ring is
/// full (the consumer must catch up first). This provides backpressure
/// without blocking the producer.
#[derive(Clone)]
pub struct SpscSender<T> {
    tx: Sender<T>,
    /// Maximum items in the ring.
    capacity: usize,
    /// Shared wakeup signal — signalled after every successful push
    /// so the consumer can block (instead of busy-spinning) when idle.
    wakeup: Arc<Wakeup>,
}

/// The consumer half of an SPSC ring. Pops values from the producer.
///
/// `pop` is non-blocking — it returns `None` when the ring is empty.
///
/// `crossbeam_channel::Receiver` is `Send + Sync`, so no `Mutex`
/// wrapper is needed (unlike `std::sync::mpsc::Receiver` which is
/// only `Send`). This eliminates the uncontended mutex lock on every
/// `pop` that the previous implementation had.
#[derive(Clone)]
pub struct SpscReceiver<T> {
    rx: Receiver<T>,
    /// Shared wakeup signal — the consumer calls `wait_for_work` on
    /// this when all rings are idle (see [`Wakeup`]).
    wakeup: Arc<Wakeup>,
}

/// Create an SPSC ring pair: (sender, receiver).
///
/// - `capacity` is the maximum number of in-flight items. When the
///   producer has `capacity` unacked items, `push` returns `Err(Full)`.
///
/// Each ring gets its own [`Wakeup`] signal. Use
/// [`spsc_ring_with_wakeup`] when multiple rings should share a
/// single wakeup (e.g. the [`RingMatcher`](crate::RingMatcher)
/// consumer thread that polls all rings).
///
/// # Panics
///
/// Panics if `capacity` is 0.
#[must_use]
pub fn spsc_ring<T>(capacity: usize) -> (SpscSender<T>, SpscReceiver<T>) {
    spsc_ring_with_wakeup(capacity, Arc::new(Wakeup::new()))
}

/// Create an SPSC ring pair sharing a caller-provided [`Wakeup`].
///
/// When multiple rings feed a single consumer thread, pass the same
/// `Wakeup` to every ring so a push on any ring wakes the consumer
/// from its idle `wait`.
///
/// # Panics
///
/// Panics if `capacity` is 0.
#[must_use]
pub fn spsc_ring_with_wakeup<T>(
    capacity: usize,
    wakeup: Arc<Wakeup>,
) -> (SpscSender<T>, SpscReceiver<T>) {
    assert!(capacity > 0, "capacity must be > 0");
    let (tx, rx) = bounded(capacity);
    (SpscSender { tx, capacity, wakeup: Arc::clone(&wakeup) }, SpscReceiver { rx, wakeup })
}

impl<T> SpscSender<T> {
    /// Push a value into the ring.
    ///
    /// Returns `Ok(())` if the value was enqueued. Returns
    /// `Err(PushError::Full(value))` if the ring is at capacity
    /// (backpressure — retry after the consumer drains). Returns
    /// `Err(PushError::Disconnected(value))` if the consumer half
    /// has been dropped (terminal — do not retry).
    ///
    /// In both error cases the value is handed back to the caller so
    /// it can retry without data loss.
    ///
    /// # Errors
    ///
    /// Returns `PushError::Full` when the ring is at capacity, or
    /// `PushError::Disconnected` when the consumer has been dropped.
    #[inline]
    pub fn push(&self, value: T) -> Result<(), PushError<T>> {
        match self.tx.try_send(value) {
            Ok(()) => {
                // Wake the consumer thread if it is blocked in
                // `wait_for_work`. This is a no-op (cheap notify)
                // when the consumer is already busy processing.
                self.wakeup.signal();
                Ok(())
            }
            Err(crossbeam_channel::TrySendError::Full(v)) => Err(PushError::Full(v)),
            Err(crossbeam_channel::TrySendError::Disconnected(v)) => {
                Err(PushError::Disconnected(v))
            }
        }
    }

    /// Returns `true` if the consumer half is still alive.
    #[inline]
    #[must_use]
    pub fn is_connected(&self) -> bool {
        !self.tx.is_empty() || self.len() < self.capacity
    }

    /// Number of items in flight (approximate).
    #[inline]
    pub fn len(&self) -> usize {
        self.tx.len()
    }

    /// Is the ring empty?
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.tx.is_empty()
    }

    /// Is the ring full?
    #[inline]
    pub fn is_full(&self) -> bool {
        self.len() >= self.capacity
    }
}

impl<T> SpscReceiver<T> {
    /// Pop a value from the ring. Returns `None` if empty.
    ///
    /// This is lock-free — `crossbeam_channel::try_recv` uses atomics
    /// internally, no kernel futex on the fast path.
    #[inline]
    pub fn pop(&self) -> Option<T> {
        self.rx.try_recv().ok()
    }

    /// Number of items in flight (approximate).
    #[inline]
    pub fn len(&self) -> usize {
        self.rx.len()
    }

    /// Is the ring empty?
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.rx.is_empty()
    }

    /// Block until the producer signals work is available, or the
    /// timeout elapses. Used by the matcher consumer thread to avoid
    /// busy-spinning when all rings are idle — see [`Wakeup`].
    ///
    /// All rings sharing the same [`Wakeup`] are woken by a push on
    /// any ring, so the consumer only needs to call this on one
    /// receiver.
    #[inline]
    pub fn wait_for_work(&self, timeout: Duration) {
        self.wakeup.wait(timeout);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

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
}
