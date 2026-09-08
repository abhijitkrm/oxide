//! Deterministic in-process mailbox — the simulation network's edge.
//!
//! # Why this exists
//!
//! A consensus simulation is a set of node tasks exchanging messages.
//! To stay deterministic (see [`crate::scheduler`] docs) the message
//! delivery order must be a function of program order only. A
//! [`Mailbox`] is a per-node FIFO queue paired with a single waker slot:
//! `send` appends to the queue and wakes the (at most one) task awaiting
//! `recv`; `recv` is a future that completes when the queue is
//! non-empty. Because sends happen in program order and the queue is
//! FIFO, the receive order is fully determined.
//!
//! # Determinism contract
//!
//! Each mailbox has exactly one consumer (one node task). `send` may be
//! called by any number of producers; the order in which producers call
//! `send` is the order messages are received. The scheduler's job is to
//! make that producer order deterministic; this module's job is to
//! preserve it through the queue without reordering.

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

/// A per-node FIFO message queue with a single waker slot.
///
/// `M: Send` because messages cross task boundaries (the sender and the
/// receiver are different spawned tasks). The mailbox itself is `Send +
/// Sync` via its `Mutex` fields, so it can be shared as `Arc<Mailbox<M>>`.
pub struct Mailbox<M> {
    queue: Mutex<VecDeque<M>>,
    waker: Mutex<Option<Waker>>,
}

impl<M> Mailbox<M> {
    /// Construct an empty mailbox.
    pub fn new() -> Self {
        Self { queue: Mutex::new(VecDeque::new()), waker: Mutex::new(None) }
    }

    /// Enqueue `msg` and wake the receiver if it is currently awaiting.
    ///
    /// Waking is idempotent: if no task is awaiting, the message simply
    /// sits in the queue and the next `recv` poll returns it
    /// immediately without needing a wake.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned. Poisoning requires a
    /// panic while the mutex is held; the only operations performed
    /// under the lock are `VecDeque::push_back` and `Waker` clone/take,
    /// none of which panic, so in correct single-threaded use this is
    /// unreachable.
    pub fn send(&self, msg: M)
    where
        M: Send,
    {
        self.queue.lock().unwrap().push_back(msg);
        // Take (not peek) the waker: a wake is a one-shot event. Leaving
        // a stale waker here would let a later `send` fire a waker whose
        // task has already been polled and re-registered a new one.
        if let Some(waker) = self.waker.lock().unwrap().take() {
            waker.wake();
        }
    }

    /// A future resolving to the next message in the queue.
    ///
    /// Takes an [`Arc`] so the future is `'static` and `Send` — required
    /// to be spawned onto the runtime. Each `recv` registers the
    /// current task's waker when the queue is empty; a subsequent
    /// `send` fires it.
    pub fn recv(this: &Arc<Self>) -> Recv<M> {
        Recv { mailbox: Arc::clone(this) }
    }
}

impl<M> Default for Mailbox<M> {
    fn default() -> Self {
        Self::new()
    }
}

/// The receive future. See [`Mailbox::recv`].
pub struct Recv<M> {
    mailbox: Arc<Mailbox<M>>,
}

impl<M> Future for Recv<M>
where
    M: Send,
{
    type Output = M;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Try to dequeue first. If a message arrived between the last
        // poll and this one (or was never awaited on), return it
        // without touching the waker slot.
        if let Some(msg) = self.mailbox.queue.lock().unwrap().pop_front() {
            return Poll::Ready(msg);
        }
        // Empty: register our waker, overwriting any previous one. The
        // previous waker, if any, belonged to a poll of this same future
        // (the only consumer) and is now stale.
        *self.mailbox.waker.lock().unwrap() = Some(cx.waker().clone());
        // Re-check after registering: a `send` between the pop_front
        // above and the waker store would have read the *old* waker slot
        // (now overwritten) and fired it — but `wake` on a waker whose
        // task is already ready is harmless (dedup in the scheduler).
        // The re-check catches the case where `send` happened before we
        // stored the waker: that send's wake was lost (no waker yet),
        // so we must observe the message ourselves.
        if let Some(msg) = self.mailbox.queue.lock().unwrap().pop_front() {
            return Poll::Ready(msg);
        }
        Poll::Pending
    }
}
