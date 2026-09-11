//! Oxide metrics — HDR histogram latency recording and Prometheus
//! exposition for node observability (plan.md §10: "measure everything").
//!
//! ## What this crate is
//!
//! A lightweight, dependency-minimal metrics layer that records
//! latency distributions per operation using HDR histograms. The
//! recorder is thread-safe (`Send + Sync`) and designed for the
//! hot path: recording a sample is a single `Histogram::record` call
//! (amortized ~40ns), and reading percentiles is O(1).
//!
//! ## Why not prometheus/metrics-rs?
//!
//! The full `metrics` crate ecosystem (`metrics-core`, `metrics-exporter-prometheus`)
//! pulls in 15+ transitive deps and a runtime. Oxide's hot-path
//! crates stay std-only (plan.md §10 rule 3). This crate provides the
//! same core capability — HDR histograms with p50/p99/p99.9 — with
//! zero non-std deps beyond `hdrhistogram` itself.
//!
//! ## Usage
//!
//! ```ignore
//! use metrics::Recorder;
//!
//! let recorder = Recorder::new();
//! recorder.record("block_pipeline", Duration::from_micros(500));
//! recorder.record("block_pipeline", Duration::from_micros(750));
//!
//! let snap = recorder.snapshot("block_pipeline");
//! println!("p50={:?} p99={:?}", snap.p50, snap.p99);
//!
//! // Prometheus exposition format for /metrics endpoint
//! let prom = recorder.prometheus();
//! ```
//!
//! ## Phase scope
//!
//! Phase 0–2 (current): latency recording + Prometheus text
//! exposition. No HTTP server — the RPC crate or a standalone
//! metrics binary exposes the `prometheus()` output.
//!
//! Phase 3+: counters, gauges, per-market trading metrics, HDR
//! histogram regression gates in CI.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use hdrhistogram::Histogram;

/// The maximum trackable latency: 60 seconds. Latencies above this
/// are clamped to the top of the histogram. This covers block
/// pipeline latencies (target: < 50ms) with 6 orders of magnitude
/// of headroom.
const MAX_LATENCY: u64 = 60_000_000;

/// The number of significant figures for the histogram. 3 means
/// the histogram maintains value resolution of 0.1% to 1% across
/// its range — sufficient for p50/p99/p99.9 discrimination.
const SIG_FIGS: u8 = 3;

/// A thread-safe latency recorder that maintains per-operation HDR
/// histograms.
///
/// Each operation name (e.g., `"block_pipeline"`, `"rpc_send_raw_tx"`)
/// gets its own `Histogram<u64>` recording nanosecond-precision
/// latencies. The recorder is `Send + Sync` and uses a `Mutex` —
/// the lock is held only during `record` (amortized ~40ns) and
/// `snapshot` (O(1) percentile lookup).
pub struct Recorder {
    histograms: Mutex<HashMap<String, Histogram<u64>>>,
}

impl Recorder {
    /// Create a new empty recorder.
    #[must_use]
    pub fn new() -> Self {
        Self { histograms: Mutex::new(HashMap::new()) }
    }

    /// Record a latency sample for the named operation.
    ///
    /// The duration is converted to nanoseconds and recorded in the
    /// operation's HDR histogram. If the operation doesn't exist
    /// yet, a new histogram is created.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn record(&self, op: &str, duration: Duration) {
        let ns = u64::try_from(duration.as_nanos().min(u128::from(MAX_LATENCY)))
            .expect("clamped to MAX_LATENCY which fits in u64");
        let mut histograms = self.histograms.lock().expect("metrics mutex not poisoned");
        histograms
            .entry(op.to_string())
            .or_insert_with(|| {
                Histogram::new_with_bounds(1, MAX_LATENCY, SIG_FIGS)
                    .expect("histogram bounds valid")
            })
            .record(ns)
            .expect("value within histogram bounds");
    }

    /// Get a snapshot of the percentiles for the named operation.
    ///
    /// Returns `None` if no samples have been recorded for the
    /// operation.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn snapshot(&self, op: &str) -> Option<LatencySnapshot> {
        let histograms = self.histograms.lock().expect("metrics mutex not poisoned");
        histograms.get(op).map(|h| LatencySnapshot {
            count: h.len(),
            min: Duration::from_nanos(h.min()),
            p50: Duration::from_nanos(h.value_at_quantile(0.5)),
            p90: Duration::from_nanos(h.value_at_quantile(0.9)),
            p99: Duration::from_nanos(h.value_at_quantile(0.99)),
            p999: Duration::from_nanos(h.value_at_quantile(0.999)),
            max: Duration::from_nanos(h.max()),
            // `h.mean()` is f64; clamp to non-negative and round before
            // truncating to u64. The mean of recorded nanosecond
            // latencies is always non-negative and well within u64 range.
            mean: Duration::from_nanos(
                {
                    #![allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                    h.mean().max(0.0).round() as u64
                },
            ),
        })
    }

    /// Generate a Prometheus text exposition of all recorded metrics.
    ///
    /// Each operation produces:
    /// - `oxide_latency_ns{op="...",percentile="50"} <value>`
    /// - `oxide_latency_ns{op="...",percentile="99"} <value>`
    /// - `oxide_latency_count{op="..."} <count>`
    ///
    /// This is the standard Prometheus text format, suitable for
    /// exposition via an HTTP `/metrics` endpoint.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn prometheus(&self) -> String {
        use std::fmt::Write;
        let histograms = self.histograms.lock().expect("metrics mutex not poisoned");
        let mut out = String::new();
        out.push_str("# HELP oxide_latency_ns Latency in nanoseconds\n");
        out.push_str("# TYPE oxide_latency_ns summary\n");
        for (op, h) in &*histograms {
            for (label, q) in [("50", 0.5), ("90", 0.9), ("99", 0.99), ("999", 0.999)] {
                let val = h.value_at_quantile(q);
                let _ =
                    writeln!(out, "oxide_latency_ns{{op=\"{op}\",percentile=\"{label}\"}} {val}");
            }
            let _ = writeln!(out, "oxide_latency_count{{op=\"{op}\"}} {}", h.len());
        }
        out
    }

    /// List all recorded operation names.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn operations(&self) -> Vec<String> {
        let histograms = self.histograms.lock().expect("metrics mutex not poisoned");
        histograms.keys().cloned().collect()
    }
}

impl Default for Recorder {
    fn default() -> Self {
        Self::new()
    }
}

/// A snapshot of latency percentiles for a single operation.
#[derive(Debug, Clone)]
pub struct LatencySnapshot {
    /// Total number of samples recorded.
    pub count: u64,
    /// Minimum observed latency.
    pub min: Duration,
    /// Median (p50) latency.
    pub p50: Duration,
    /// 90th percentile latency.
    pub p90: Duration,
    /// 99th percentile latency.
    pub p99: Duration,
    /// 99.9th percentile latency.
    pub p999: Duration,
    /// Maximum observed latency.
    pub max: Duration,
    /// Mean (average) latency.
    pub mean: Duration,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_and_snapshot() {
        let r = Recorder::new();
        r.record("test_op", Duration::from_micros(100));
        r.record("test_op", Duration::from_micros(200));
        r.record("test_op", Duration::from_micros(300));
        let snap = r.snapshot("test_op").expect("snapshot exists");
        assert_eq!(snap.count, 3);
        assert!(snap.p50 >= Duration::from_micros(100));
        assert!(snap.p50 <= Duration::from_micros(300));
        assert!(snap.max >= Duration::from_micros(300));
    }

    #[test]
    fn snapshot_missing_op_returns_none() {
        let r = Recorder::new();
        assert!(r.snapshot("nonexistent").is_none());
    }

    #[test]
    fn prometheus_format() {
        let r = Recorder::new();
        r.record("block_pipeline", Duration::from_micros(500));
        let prom = r.prometheus();
        assert!(prom.contains("oxide_latency_ns{op=\"block_pipeline\""));
        assert!(prom.contains("oxide_latency_count{op=\"block_pipeline\"}"));
    }

    #[test]
    fn operations_list() {
        let r = Recorder::new();
        r.record("op_a", Duration::from_micros(1));
        r.record("op_b", Duration::from_micros(1));
        let ops = r.operations();
        assert!(ops.contains(&"op_a".to_string()));
        assert!(ops.contains(&"op_b".to_string()));
    }

    #[test]
    fn latency_clamped_to_max() {
        let r = Recorder::new();
        // 120 seconds — above the 60s max. Should be clamped, not panic.
        r.record("big_op", Duration::from_secs(120));
        let snap = r.snapshot("big_op").expect("snapshot exists");
        assert!(snap.max <= Duration::from_secs(60));
    }
}
