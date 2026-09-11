//! Lock-free SPSC (single-producer, single-consumer) ring buffer.
//!
//! The LMAX Disruptor pattern for the matching server: each TCP
//! connection writes to its own ring; a single matcher thread reads
//! from all rings round-robin. Zero mutexes, zero contention.
//!
//! # Design
//!
//! Uses `std::sync::mpsc` channels internally — the bounded channel
//! is already a lock-free SPSC ring. The `SpscSender`/`SpscReceiver`
//! pair splits the channel into producer and consumer halves.
//!
//! # Why not crossbeam?
//!
//! `crossbeam::channel` is a general-purpose MPMC channel with more
//! overhead than needed. `std::sync::mpsc` is sufficient for SPSC
//! and is already in the stdlib.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};

/// The producer half of an SPSC ring. Pushes values to the consumer.
///
/// `push` is non-blocking — it returns `false` when the ring is
/// full (the consumer must catch up first). This provides
/// backpressure without blocking the producer.
#[derive(Clone)]
pub struct SpscSender<T> {
    tx: Sender<T>,
    /// Shared in-flight counter (producer increments, consumer
    /// decrements). Provides backpressure without blocking.
    in_flight: Arc<AtomicUsize>,
    /// Maximum items in the ring.
    capacity: usize,
}

/// The consumer half of an SPSC ring. Pops values from the producer.
///
/// `pop` is non-blocking — it returns `None` when the ring is empty.
///
/// The `mpsc::Receiver` is `Send` but not `Sync`, so it lives behind
/// an `Arc<Mutex<_>>` to make the receiver shareable across await
/// points. The consumer is single-threaded per ring, so the mutex
/// is uncontended in practice — it's a formality for `Sync`.
#[derive(Clone)]
pub struct SpscReceiver<T> {
    rx: Arc<std::sync::Mutex<Receiver<T>>>,
    /// Shared in-flight counter (producer increments, consumer
    /// decrements).
    in_flight: Arc<AtomicUsize>,
}

/// Create an SPSC ring pair: (sender, receiver).
///
/// - `capacity` is the maximum number of in-flight items. When the
///   producer has `capacity` unacked items, `push` returns `false`.
///
/// # Panics
///
/// Panics if `capacity` is 0.
#[must_use]
pub fn spsc_ring<T>(capacity: usize) -> (SpscSender<T>, SpscReceiver<T>) {
    assert!(capacity > 0, "capacity must be > 0");
    let (tx, rx) = channel();
    let in_flight = Arc::new(AtomicUsize::new(0));
    (
        SpscSender { tx, in_flight: Arc::clone(&in_flight), capacity },
        SpscReceiver { rx: Arc::new(std::sync::Mutex::new(rx)), in_flight },
    )
}

impl<T> SpscSender<T> {
    /// Push a value into the ring. Returns `false` if the ring is
    /// full (backpressure) or the channel is disconnected.
    #[inline]
    pub fn push(&self, value: T) -> bool {
        if self.in_flight.load(Ordering::Relaxed) >= self.capacity {
            return false; // Backpressure: ring is full.
        }
        if self.tx.send(value).is_err() {
            return false; // Channel disconnected.
        }
        self.in_flight.fetch_add(1, Ordering::Relaxed);
        true
    }

    /// Number of items in flight (approximate).
    #[inline]
    pub fn len(&self) -> usize {
        self.in_flight.load(Ordering::Relaxed)
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

impl<T> SpscReceiver<T> {
    /// Pop a value from the ring. Returns `None` if empty.
    ///
    /// # Panics
    ///
    /// Panics if the internal receiver mutex is poisoned.
    #[inline]
    pub fn pop(&self) -> Option<T> {
        let rx = self.rx.lock().unwrap();
        match rx.try_recv() {
            Ok(v) => {
                drop(rx);
                self.in_flight.fetch_sub(1, Ordering::Relaxed);
                Some(v)
            }
            Err(_) => None,
        }
    }

    /// Number of items in flight (approximate).
    #[inline]
    pub fn len(&self) -> usize {
        self.in_flight.load(Ordering::Relaxed)
    }

    /// Is the ring empty?
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
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
        assert!(tx.push(42));
        assert_eq!(rx.len(), 1);
        assert_eq!(rx.pop(), Some(42));
        assert!(rx.is_empty());
    }

    #[test]
    fn ring_full() {
        let (tx, rx) = spsc_ring::<u64>(4);
        for i in 0..4 {
            assert!(tx.push(i));
        }
        assert!(tx.is_full());
        assert!(!tx.push(5)); // Full.
        assert_eq!(rx.pop(), Some(0));
        assert!(tx.push(5)); // Now fits.
    }

    #[test]
    fn spsc_concurrent() {
        let (tx, rx) = spsc_ring::<u64>(1024);

        let producer = thread::spawn(move || {
            for i in 0..10_000u64 {
                while !tx.push(i) {
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
