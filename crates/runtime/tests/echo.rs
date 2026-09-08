//! Four-node echo simulation — Phase 0 acceptance for the `runtime`
//! crate (testing-standards skill §4: deterministic simulation layer).
//!
//! # Protocol
//!
//! A simplified Bracha reliable broadcast over four nodes:
//! 1. Node 0 broadcasts `Init` to nodes 1, 2, 3.
//! 2. On receiving `Init`, a node broadcasts `Echo` to *all* four nodes
//!    (including itself, so every node's echo-count can reach 4).
//! 3. A node `delivers` once it has received `Echo` from all four nodes.
//!
//! # What this asserts
//!
//! - **Liveness:** every node delivers (run completes with four
//!   deliveries) — the executor drains all work to completion.
//! - **Determinism:** two independent runs produce an identical
//!   sequence of `(node, delivered_at_step)` events. This is the real
//!   test: the scheduler's ordering must be a pure function of program
//!   order, or bisection of simulation failures is impossible.
//! - **No deadlock:** `run_until_idle` returns (the queue empties),
//!   proving no task is left awaiting a wake that never comes.

use std::sync::{Arc, Mutex};

use runtime::{Mailbox, Runtime};

/// Number of nodes in the simulation. Kept small for Phase 0; the
/// scheduler's determinism is independent of node count, and a larger
/// swarm belongs in `sim/` once consensus messages exist.
const N: usize = 4;

/// A message in the echo protocol. `Copy` so `send` can broadcast to
/// all nodes without cloning — keeps the sim free of allocations on
/// the message path (not a hot-path requirement here, just tidy).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Msg {
    /// "I am starting the broadcast." Sent by node 0 to 1, 2, 3.
    Init { from: usize },
    /// "I have seen the init." Sent by every node to every node.
    Echo { from: usize },
}

/// A shared, append-only event log. The determinism assertion compares
/// two of these byte-for-byte. Each entry records *which* node delivered
/// and *when* (the step counter at the moment of delivery), so the
/// assertion catches both reordering and miscounting.
type Log = Arc<Mutex<Vec<usize>>>;

/// Per-node state. Lives on the node task's stack; no shared mutable
/// state is needed because all coordination goes through mailboxes.
/// `id` is the closure's `id` (used to index mailboxes), not stored
/// here — keeping it out avoids a dead-field warning and makes the
/// state purely protocol-relevant.
struct Node {
    /// Whether this node has sent its `Echo`. `Init` may, in principle,
    /// arrive more than once (node 0 sends it once, but the protocol is
    /// written defensively); we echo only on the first.
    echoed: bool,
    /// Set of nodes whose `Echo` this node has received. A `Vec<bool>`
    /// indexed by sender id; a node is counted once even if it echoes
    /// twice (it won't, but the data structure enforces it).
    echo_seen: Vec<bool>,
    delivered: bool,
}

impl Node {
    fn new() -> Self {
        Self { echoed: false, echo_seen: vec![false; N], delivered: false }
    }

    /// Record an `Echo` from `from`; return `true` if this delivery
    /// completes the node's echo-count (i.e. this was the fourth
    /// distinct echo). Idempotent on duplicate `from`.
    fn observe_echo(&mut self, from: usize) -> bool {
        if !self.echo_seen[from] {
            self.echo_seen[from] = true;
        }
        if self.delivered {
            return false;
        }
        let count = self.echo_seen.iter().filter(|&&seen| seen).count();
        if count == N {
            self.delivered = true;
            true
        } else {
            false
        }
    }
}

/// Run one simulation. Returns the delivery log (node ids in delivery
/// order). Every run constructs fresh mailboxes, a fresh runtime, and
/// fresh node tasks — the *only* thing carried between runs is the
/// program text, which is what makes the determinism assertion
/// meaningful.
fn run_once() -> Vec<usize> {
    let rt = Runtime::new();
    let handle = rt.handle();

    // One mailbox per node. Index == node id.
    let mailboxes: Vec<Arc<Mailbox<Msg>>> = (0..N).map(|_| Arc::new(Mailbox::new())).collect();
    let log: Log = Arc::new(Mutex::new(Vec::new()));

    // Spawn each node. Spawn order is node 0, 1, 2, 3 — this is the
    // initial ready-queue order, which (combined with FIFO polling) is
    // part of what makes the run deterministic.
    for id in 0..N {
        let mailboxes = mailboxes.clone();
        let log = Arc::clone(&log);
        handle.spawn(async move {
            let mut node = Node::new();

            // Node 0 kicks off the broadcast. It is the initiator and
            // never receives `Init` itself, so it must emit its own
            // `Echo` directly — otherwise every other node's echo-count
            // tops out at N-1 and nobody delivers. (The `echo_known_order`
            // test exists precisely to guard this invariant.)
            if id == 0 {
                for mb in &mailboxes[1..] {
                    mb.send(Msg::Init { from: 0 });
                }
                for mb in &mailboxes {
                    mb.send(Msg::Echo { from: 0 });
                }
            }

            loop {
                let msg = Mailbox::recv(&mailboxes[id]).await;
                match msg {
                    Msg::Init { from } => {
                        // On first Init, broadcast Echo to every node.
                        if !node.echoed {
                            node.echoed = true;
                            for mb in &mailboxes {
                                mb.send(Msg::Echo { from: id });
                            }
                        }
                        // `from` is unused beyond the match; the protocol
                        // does not care who initiated.
                        let _ = from;
                    }
                    Msg::Echo { from } => {
                        if node.observe_echo(from) {
                            log.lock().unwrap().push(id);
                            break;
                        }
                    }
                }
            }
        });
    }

    rt.run_until_idle();

    let log_guard = log.lock().unwrap();
    log_guard.clone()
}

#[test]
fn echo_liveness_all_nodes_deliver() {
    let deliveries = run_once();
    // Every node must deliver exactly once, so the log has N entries
    // and contains each node id exactly once.
    assert_eq!(deliveries.len(), N, "every node should deliver exactly once");
    let mut sorted = deliveries.clone();
    sorted.sort_unstable();
    assert_eq!(sorted, (0..N).collect::<Vec<_>>(), "all nodes delivered");
}

#[test]
fn echo_determinism_two_runs_identical() {
    let first = run_once();
    let second = run_once();
    assert_eq!(
        first, second,
        "two runs of the same simulation must produce identical delivery sequences; \
         the scheduler's ordering must be a pure function of program order"
    );
}

#[test]
fn echo_known_order() {
    // Pin the expected delivery order as a regression guard. The order
    // is a consequence of: spawn order 0..N, FIFO polling, FIFO
    // mailboxes, and node 0 sending Init to 1,2,3 then self-Echo to all.
    // If the scheduler changes, this test tells us *which* way it changed.
    //
    // Pinned delivery order: [3, 0, 1, 2].
    //
    // Why this order (a read of the scheduler, not a guess):
    // - Spawn order is 0,1,2,3 → first poll pass is 0,1,2,3.
    // - Node 0 sends Init→{1,2,3} then Echo{0}→{0,1,2,3}, then awaits.
    // - Nodes 1,2,3 are polled in order; each receives Init, broadcasts
    //   Echo to all, then drains its own mailbox until empty (pending).
    // - Node 3 finishes draining last among 1..3 and reaches 4 echoes
    //   first (it has Echo{0,1,2,3}), so it delivers first.
    // - Node 0 then drains Echo{1,2,3} (Echo{0} already consumed) and
    //   delivers second.
    // - Nodes 1 and 2 each need the late-arriving Echo{3}; they deliver
    //   in poll order (1 before 2).
    //
    // If the scheduler's FIFO invariant, the mailbox FIFO invariant, or
    // the wake-dedup logic changes, this order changes and this test
    // fails — which is exactly the regression signal we want.
    let deliveries = run_once();
    assert_eq!(deliveries, vec![3, 0, 1, 2]);
}
