//! Deterministic single-threaded executor.
//!
//! # Why this exists
//!
//! The top of Oxide's five-layer test pyramid (testing-standards skill §4)
//! is *deterministic simulation*: replaying a multi-node scenario must
//! produce byte-identical results every run, otherwise a flaky failure
//! cannot be bisected. `tokio` and the OS scheduler are deliberately
//! *non*-deterministic — they wake tasks in whatever order the runtime
//! and the kernel see fit. This crate provides the opposite: a
//! single-threaded, std-only executor whose scheduling order is fully
//! determined by program order.
//!
//! # Scheduling rule (the determinism contract)
//!
//! The ready queue is a FIFO. A task is polled at most once per
//! [`Runtime::run_until_idle`] pass when ready; if it returns
//! `Poll::Pending` it is re-enqueued *only* when its [`Waker`] is fired,
//! and the enqueue goes to the back of the queue. Wakers fire in the
//! order messages are sent (see [`crate::mailbox`]); combined with FIFO
//! polling this makes the entire execution a deterministic function of
//! the inputs. Two runs with identical inputs produce identical event
//! logs — asserted by `tests/echo.rs`.
//!
//! # Safety
//!
//! No `unsafe` (workspace denies it). `Send + Sync` on [`Task`] is
//! achieved with `Mutex`; the mutexes are never contended because only
//! the single runtime thread ever locks them — they exist purely to
//! satisfy `std::task::Wake`'s `Self: Send + Sync` requirement.

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Wake, Waker};

/// Shared scheduler state: the ready queue. Held in an [`Arc`] so that
/// wakers — which outlive any borrow of [`Runtime`] — can reach it from
/// inside a polled future.
struct Scheduler {
    ready: Mutex<VecDeque<Arc<Task>>>,
}

/// A spawned future plus its link back to the scheduler.
///
/// `queued` is a dedup flag: `Wake::wake` may be called many times
/// between polls (a future often stores its waker and a downstream
/// component also fires it). Without dedup the same task could appear
/// in the ready queue multiple times, which would make the poll order
/// depend on how many redundant wakes happened — breaking determinism.
struct Task {
    /// The future, behind a `Mutex` only to satisfy `Sync` (see crate
    /// docs). `Option` so a completed future can be dropped in place;
    /// a late wake of a completed task is a no-op (handled in
    /// [`Runtime::run_until_idle`]).
    future: Mutex<Option<Pin<Box<dyn Future<Output = ()> + Send>>>>,
    /// Back-reference enabling `Wake` to enqueue `self` without a
    /// captured `Arc<Runtime>` (which would be a cycle).
    sched: Arc<Scheduler>,
    /// Whether this task is already in the ready queue. `Relaxed`
    /// ordering is sufficient: only the single runtime thread reads and
    /// writes it, so there is no cross-thread synchronization to enforce.
    queued: AtomicBool,
}

impl Wake for Task {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        // Already queued: a redundant wake. Dropping it preserves the
        // one-task-one-slot invariant that makes poll order deterministic.
        if self.queued.swap(true, Ordering::Relaxed) {
            return;
        }
        self.sched
            .ready
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push_back(self.clone());
    }
}

/// A handle that can spawn tasks. Cheap to clone (`Arc`); pass it into
/// futures that need to spawn subtasks.
#[derive(Clone)]
pub struct Handle {
    sched: Arc<Scheduler>,
}

impl Handle {
    /// Spawn a future onto the runtime. It becomes ready immediately
    /// (first poll happens on the next `run_until_idle`).
    ///
    /// # Panics
    ///
    /// Panics if the ready-queue mutex is poisoned. Poisoning requires a
    /// panic while the lock is held; the only operation under the lock
    /// is `VecDeque::push_back`, which does not panic, so in correct
    /// single-threaded use this is unreachable.
    pub fn spawn<F>(&self, fut: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let task = Arc::new(Task {
            future: Mutex::new(Some(Box::pin(fut))),
            sched: self.sched.clone(),
            // Starts queued so the first poll happens without an explicit wake.
            queued: AtomicBool::new(true),
        });
        self.sched.ready.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push_back(task);
    }
}

/// The deterministic runtime. Owns the ready queue; drop it to tear down.
pub struct Runtime {
    sched: Arc<Scheduler>,
}

impl Runtime {
    /// Construct an empty runtime.
    pub fn new() -> Self {
        Self { sched: Arc::new(Scheduler { ready: Mutex::new(VecDeque::new()) }) }
    }

    /// A clonable handle for spawning from inside tasks.
    pub fn handle(&self) -> Handle {
        Handle { sched: self.sched.clone() }
    }

    /// Spawn a future onto the runtime.
    pub fn spawn<F>(&self, fut: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        self.handle().spawn(fut);
    }

    /// Poll ready tasks until the ready queue is empty.
    ///
    /// Re-entrant wakes (from inside a poll) go to the back of the queue
    /// and are drained in the same pass. Returns when no task is ready —
    /// i.e. every spawned task is either completed or awaiting a wake
    /// that the runtime cannot self-generate (it must come from an
    /// external source, which in simulations is the next message sent
    /// via a [`crate::mailbox::Mailbox`]).
    ///
    /// # Panics
    ///
    /// Panics if the ready-queue mutex is poisoned. Poisoning requires a
    /// panic while the lock is held; the only operation under that lock
    /// is `VecDeque::pop_front`, which does not panic, so in correct
    /// single-threaded use this is unreachable. A panic *inside* a
    /// polled future unwinds out of `run_until_idle` (the workspace
    /// `panic = "unwind"` profile); the per-task future mutex it leaves
    /// poisoned is never re-locked because the panicking task is
    /// dropped on unwind.
    pub fn run_until_idle(&self) {
        loop {
            let task = self
                .sched
                .ready
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .pop_front();
            let Some(task) = task else {
                return;
            };
            // Mark not-queued *before* polling: a wake during this poll
            // must be able to re-enqueue. (Set after poll would miss
            // self-wakes.)
            task.queued.store(false, Ordering::Relaxed);

            let waker = Waker::from(task.clone());
            let mut cx = Context::from_waker(&waker);

            // Hold the future lock only across the poll. A wake during
            // poll locks `ready` (a different mutex) — no deadlock.
            let mut slot = task.future.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let Some(fut) = slot.as_mut() else {
                // A completed task woken late: drop the dedup flag is
                // already false; just skip. No re-enqueue.
                continue;
            };
            if fut.as_mut().poll(&mut cx).is_ready() {
                // Done: drop the future in place so its resources are
                // released before the task's `Arc` refcount hits zero.
                *slot = None;
            }
            // Pending: the future has stored a waker; it will be
            // re-enqueued when that waker fires.
        }
    }
}

impl Default for Runtime {
    fn default() -> Self {
        Self::new()
    }
}
