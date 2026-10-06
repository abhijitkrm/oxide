//! Async execution lane — backlog drain behind the consensus
//! caller.
//!
//! Split from `lib.rs` around the offload invariant:
//! [`Executor::spawn_exec_lane`] moves committed-block execution
//! off the consensus thread; `execute_committed_backlog` is the
//! single drain loop, and `insert_finalized` is the only writer
//! of the finalized map from that lane. If the lane dies,
//! [`LaneDeath`] (declared in `lib.rs`) fails loudly rather than
//! leaving finalized blocks unexecuted.

use super::{Executor, FinalizedBlock, InsertRetained, LaneDeath};

impl Executor {
    /// Phase D: enable the async execution lane.
    ///
    /// When enabled, `finalize_block` defers execution to overlap
    /// with consensus. The pending block is executed lazily when
    /// `attest_state` is called or when the next `finalize_block`
    /// flushes it.
    ///
    /// This trades a small per-block overhead for the ability to
    /// overlap execution of block h-1 with consensus for block h.
    /// For the full consensus pipeline (2-chain), this can hide
    /// execution latency behind consensus latency.
    /// Spawn the async execution worker. `finalize_block` then
    /// hands each committed block to the worker and returns
    /// immediately; the worker executes it and records the state
    /// root — overlapping execution of block h with consensus for
    /// block h+1, instead of serializing both on the consensus
    /// thread.
    ///
    /// # Correctness
    ///
    /// Blocks arrive strictly in commit order (the engine's commit
    /// walk is contiguous and oldest-first), so the worker's serial
    /// execution matches the synchronous path's ordering exactly.
    /// `attest_state(h)` waits on the watermark while h is
    /// enqueued-but-not-executed — the same root the synchronous
    /// path would have produced, just computed off-thread.
    ///
    /// The worker holds a `Weak` back-reference: dropping the
    /// `Executor` disconnects the channel and the thread exits —
    /// no reference cycle leaks the executor through its own
    /// worker.
    ///
    /// # Panics
    ///
    /// Panics if called twice — a second lane would split the
    /// commit stream.
    pub fn spawn_exec_lane(self: &std::sync::Arc<Self>) {
        // Once-only: two workers would split the commit stream.
        self.exec_lane_once.set(()).expect("exec lane already spawned");
        let weak = std::sync::Arc::downgrade(self);
        let sync = self.exec_sync.clone();
        {
            let (lock, _cv) = &*sync;
            primitives::sync::lock_state(lock).lane_spawned = true;
        }
        // Supervised + critical: this lane is the only path from
        // finalized block to executed state root. A panic here means
        // `attest_state`/`drain` can never complete — fail fast so the
        // supervisor restarts rather than livelock on withheld votes.
        // Pinned (hft-audit F-02): `exec_lane_core` keeps the whole
        // block-execute → attest path on one core so its cache
        // locality isn't re-warmed on every migrate; `None` runs
        // unpinned (dev/test default).
        primitives::supervision::spawn_supervised_pinned(
            "exec-lane",
            true,
            self.exec_lane_core,
            move || {
                // RAII: ANY worker exit — panic unwind or clean
                // disconnect — marks the lane dead and wakes
                // every waiter. Without this, a panic mid-`execute_block`
                // left `attest_state` waiting forever on a watermark
                // that could never advance, and the death surfaced
                // only as unexplained withheld votes.
                let _death = LaneDeath { sync: sync.clone() };
                loop {
                    // Drain every committed block currently queued, waiting
                    // on the condvar while the deque is empty. The commit
                    // path pushes under the same lock and never blocks —
                    // the `saturated` flag (not a full queue) is what
                    // throttles consensus when we fall behind.
                    let batch = {
                        let (lock, cv) = &*sync;
                        let mut s = primitives::sync::lock_state(lock);
                        loop {
                            if !s.pending.is_empty() {
                                // Fully drained = caught up: clear the
                                // saturation signal so the engine resumes
                                // voting and committing. Clearing only on
                                // empty (not merely below the threshold)
                                // keeps the flag honest — a half-drained
                                // backlog is still debt.
                                let batch: Vec<FinalizedBlock> = s.pending.drain(..).collect();
                                s.saturated = false;
                                break batch;
                            }
                            // If the executor is gone there is no one left
                            // to serve — exit rather than resurrect it.
                            if weak.upgrade().is_none() {
                                return;
                            }
                            s = cv.wait(s).unwrap_or_else(|_| {
                                panic!("state mutex poisoned: a holder panicked mid-mutation")
                            });
                        }
                    };
                    // The upgrade is redone post-pop: the executor could
                    // have dropped between the wait check and here.
                    let Some(executor) = weak.upgrade() else { return };
                    // Journal ⊇ durable state: the batch's journal
                    // records (buffered on the commit thread) become
                    // durable in ONE fsync here, before any block's
                    // `execute_block` can flush module state to its own
                    // backend. Batching is the whole point — the commit
                    // thread used to pay one fsync per finalized block.
                    executor.journal_sync_pending();
                    for block in batch {
                        let height = block.height.value();
                        // Mark the block in-flight BEFORE executing: if
                        // `execute_block` panics below, `LaneDeath` fires
                        // with this set and no root recorded — the state
                        // the recovery path must treat as partially
                        // applied, never blindly replayed.
                        {
                            let (lock, _cv) = &*sync;
                            primitives::sync::lock_state(lock).in_flight = Some(height);
                        }
                        let root = executor.execute_block(&block);
                        primitives::sync::lock_state(&executor.state_roots).insert_retained(
                            height,
                            root,
                            executor.history_retention,
                        );
                        // Blocks arrive in commit order, so the newest
                        // height is always the watermark.
                        let (lock, cv) = &*sync;
                        {
                            let mut s = primitives::sync::lock_state(lock);
                            s.in_flight = None;
                            s.executed = Some(height);
                        }
                        cv.notify_all();
                    }
                }
            },
        )
        .expect("spawn exec lane thread");
    }

    /// Drive every committed-but-unexecuted height through block
    /// execution inline, in commit order. Called when the async
    /// lane is dead or unreachable: `finalized` already holds the
    /// committed blocks, so nothing is lost — the lane is only an
    /// offload, never the owner of correctness. Roots land in
    /// `state_roots` exactly as the worker would have written them,
    /// and the `executed` watermark advances to the newest root so
    /// `attest_state` waiters see the lane's debt as settled.
    ///
    /// A deterministic panic in `execute_block` propagates to the
    /// caller: a committed block that cannot execute is a fatal,
    /// chain-level fault. Crashing on the committing thread with
    /// the real panic is honest failure propagation — masking it
    /// would convert a loud crash into a silent liveness stall.
    ///
    /// # Panics
    ///
    /// Panics when the dead lane was mid-`execute_block` on a height
    /// that never recorded a root: that block was PARTIALLY APPLIED
    /// (fees charged, nonces advanced, module state mutated for some
    /// prefix of its txs), and re-executing it would replay those
    /// mutations on already-mutated state — potentially producing a
    /// silently wrong root rather than a second panic. There is no
    /// whole-block rollback to restore the pre-block state, so the
    /// only safe course is to halt: recovery must come from durable
    /// state (journal/snapshot/backend) at process restart. Heights
    /// the lane never started are unaffected — replaying an
    /// unstarted block mutates nothing twice.
    /// Insert a committed block into `finalized` and prune to the
    /// retention window — but never evict a height that has not
    /// been executed. Unexecuted committed blocks are the backlog
    /// the inline drain replays on lane failure; pruning one would
    /// strand that height permanently rootless. Execution is in
    /// height order, so every height at or below the `executed`
    /// watermark already has a root and is safe to drop; the pin
    /// simply refuses to evict above it.
    ///
    /// The watermark is read before the map lock — two short,
    /// non-nested critical sections keep the lock graph flat. A
    /// stale read only makes eviction more conservative, never
    /// wrong.
    pub(crate) fn insert_finalized(&self, height: u64, block: FinalizedBlock) {
        let executed = {
            let (lock, _cv) = &*self.exec_sync;
            primitives::sync::lock_state(lock).executed
        };
        let mut f = primitives::sync::lock_state(&self.finalized);
        f.insert(height, block);
        while f.len() > self.history_retention {
            let evictable =
                f.keys().next().is_some_and(|first| executed.is_some_and(|e| *first <= e));
            if !evictable {
                break;
            }
            f.pop_first();
        }
    }

    pub(crate) fn execute_committed_backlog(&self) {
        // Journal ⊇ durable state: anything this drain is about to
        // execute was buffered (unsynced) by `journal_append` — make
        // it durable before the first block's module flush. One sync
        // covers the whole backlog.
        self.journal_sync_pending();
        // Fail closed on a partially applied block before replaying
        // anything. `in_flight` is set by the worker around
        // `execute_block` and cleared only after the root lands, so
        // `Some(h)` + no root = the worker died mid-mutation.
        let poisoned = {
            let (lock, _cv) = &*self.exec_sync;
            let in_flight = primitives::sync::lock_state(lock).in_flight;
            in_flight.filter(|h| !primitives::sync::lock_state(&self.state_roots).contains_key(h))
        };
        if let Some(h) = poisoned {
            panic!(
                "executor: execution lane died mid-execution of committed block {h}; \
                 the block may be partially applied (fees/nonces/module state already \
                 mutated) and cannot be safely replayed in-process — halting; restart \
                 to recover from durable state"
            );
        }
        loop {
            // Oldest committed height still lacking a state root —
            // height order preserves the worker's serial ordering
            // exactly. Two short critical sections, never nested:
            // no lock-order contract between the block log and the
            // root map.
            let next = {
                let heights: Vec<u64> =
                    primitives::sync::lock_state(&self.finalized).keys().copied().collect();
                let roots = primitives::sync::lock_state(&self.state_roots);
                heights.into_iter().find(|h| !roots.contains_key(h))
            };
            let Some(height) = next else { break };
            let Some(block) = primitives::sync::lock_state(&self.finalized).get(&height).cloned()
            else {
                // The entry was found moments ago and this thread is
                // the only pruner — unreachable, but bail rather
                // than spin if invariants ever change.
                break;
            };
            // Mark the height in-flight around the inline execution
            // exactly as the worker does: if `execute_block` panics
            // here, the panic propagates to the committer AND the
            // marker stays set — so a later `finalize_block` meets
            // the same fail-closed check above instead of silently
            // retrying a block this drain partially applied.
            {
                let (lock, _cv) = &*self.exec_sync;
                primitives::sync::lock_state(lock).in_flight = Some(height);
            }
            let root = self.execute_block(&block);
            primitives::sync::lock_state(&self.state_roots).insert_retained(
                height,
                root,
                self.history_retention,
            );
            {
                let (lock, _cv) = &*self.exec_sync;
                primitives::sync::lock_state(lock).in_flight = None;
            }
        }
        // Advance the executed watermark to the newest recorded
        // root: heights the dead lane owed have now been executed
        // inline, and `attest_state` waiters must observe that.
        let newest =
            primitives::sync::lock_state(&self.state_roots).iter().next_back().map(|(h, _)| *h);
        if let Some(h) = newest {
            let (lock, cv) = &*self.exec_sync;
            let mut s = primitives::sync::lock_state(lock);
            s.executed = Some(s.executed.map_or(h, |e| e.max(h)));
            cv.notify_all();
        }
    }
}
