//! Port reservation for multi-node tests.
//!
//! The TCP devnet binds `base_port + i` for each validator, and the
//! tests used to hard-code those bases (21000–21700, 30000+ from a
//! per-process counter). A hard-coded range is shared with every
//! other process on the machine — another test binary, a running
//! devnet, any service — and a single collision panics the
//! transport's `bind` and fails the whole suite at once. That is
//! what an 8-run full-suite sweep caught: every `byzantine` test
//! failing together in one run.
//!
//! [`reserve`] instead starts at a process-specific offset (so
//! concurrent test processes do not race for the same block) and
//! probes that every port in the span is bindable on the address the
//! transport uses before handing it out. A probe-then-bind window
//! remains, but it is microseconds instead of the whole run.

use std::net::TcpListener;
use std::sync::atomic::{AtomicU32, Ordering};

/// Lowest port handed out — above the hard-coded production defaults
/// (20000/24000-class) and below the OS ephemeral range (≥ 49152 on
/// macOS; Linux ephemeral ports start at 32768, which a busy box can
/// reach — the bind probe below covers that case).
const FLOOR: u32 = 30_000;
/// Size of the reservation window: `[FLOOR, FLOOR + WINDOW)`.
const WINDOW: u32 = 18_000;

/// Reserve `span` consecutive free ports on 127.0.0.1 and return the
/// first. Panics only if no free span is found after scanning the
/// whole window — a machine with tens of thousands of bound ports.
///
/// # Panics
///
/// When the entire window is occupied.
#[doc(hidden)]
#[must_use]
pub fn reserve(span: u16) -> u16 {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let span32 = u32::from(span.max(1));
    // Spread processes apart: pid picks a 100-port slot.
    let start = (std::process::id() % (WINDOW / 100)) * 100;
    let tries = WINDOW / span32;
    for _ in 0..tries {
        let offset = NEXT.fetch_add(span32, Ordering::SeqCst);
        let base = FLOOR + (start + offset) % (WINDOW - span32);
        let all_free = (0..span32).all(|i| {
            u16::try_from(base + i).is_ok_and(|p| TcpListener::bind(("127.0.0.1", p)).is_ok())
        });
        if all_free {
            return u16::try_from(base).expect("window stays below 65536");
        }
    }
    panic!("no {span} consecutive free ports in {FLOOR}..{}", FLOOR + WINDOW);
}

#[cfg(test)]
mod tests {
    use super::reserve;

    /// A reserved span is free, and consecutive reservations in one
    /// process never overlap.
    #[test]
    fn reservations_are_free_and_disjoint() {
        let a = reserve(8);
        let b = reserve(8);
        assert!(a.abs_diff(b) >= 8, "spans overlap: {a} and {b}");
        for p in a..a + 8 {
            assert!(std::net::TcpListener::bind(("127.0.0.1", p)).is_ok(), "port {p} not free");
        }
    }

    /// An occupied port inside the next span is skipped, not handed
    /// out — the collision the hard-coded bases suffered.
    #[test]
    fn occupied_ports_are_skipped() {
        let probe = reserve(4);
        let _held = std::net::TcpListener::bind(("127.0.0.1", probe + 4)).expect("hold a port");
        let next = reserve(4);
        assert!(!(next..next + 4).contains(&(probe + 4)), "handed out a held port");
    }
}
