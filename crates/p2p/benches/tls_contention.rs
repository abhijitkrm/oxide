//! TLS transport contention benchmark — audit001 §7.5's last named
//! measurement.
//!
//! Oxide's TCP transport writes to a `try_clone()`d socket, so a slow
//! reader never blocks a writer. TLS has no equivalent: rustls streams
//! are one object, so the transport wraps them in `SharedStream` — an
//! `Arc<Mutex<S>>` shared by the reader thread and every writer. The
//! reader polls with `TLS_READER_POLL_TIMEOUT` (500 ms) under that
//! mutex, yielding 1 ms between polls so writers can slip in
//! (`tcp.rs` `reader_loop`). This bench measures what that discipline
//! costs a writer: frame latency on the shared mutex while a reader
//! holds it through a blocking poll, for both the real mTLS crypto
//! path and a plaintext `TcpStream` baseline.
//!
//! Informational only — no hard gate. The numbers answer the audit's
//! question "is `Arc<Mutex<TlsStream>>` a live bottleneck under HFT
//! load?", not a per-release regression bound.

#![allow(missing_docs)]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use p2p::tcp::{FrameReader, PeerStream, SharedStream, bench_tls_configs, bench_tls_connect};

/// Matches `DEFAULT_MAX_MESSAGE_BYTES` in `tcp.rs` — frame decode
/// limit, not exercised by these payload sizes.
const MAX_MSG: u64 = 16 << 20;

/// Scaled-down stand-in for `TLS_READER_POLL_TIMEOUT` (500 ms) used by
/// the thread-scaling rows: same shape (blocking poll under the mutex,
/// 1 ms yield) at a poll interval short enough for criterion to get
/// samples. The `p500` rows run the production value so the report
/// carries the true number too.
const BENCH_POLL: Duration = Duration::from_millis(20);
const PROD_POLL: Duration = Duration::from_millis(500);

/// Reader yield between empty polls — identical to the `reader_loop`
/// sleep that gives writers a mutex window (tcp.rs).
const READER_YIELD: Duration = Duration::from_millis(1);

/// `Read + Write + Send` combined so TLS and plaintext streams share
/// one `SharedStream` instantiation — `rustls` types stay unnameable
/// from the bench crate (no rustls dep of its own).
trait IoStream: Read + Write + Send {}
impl<T: Read + Write + Send> IoStream for T {}
type Shared = SharedStream<Box<dyn IoStream>>;

/// Drive `writers` concurrent `write_frame` threads against `shared`
/// while a reader thread polls under the same mutex (production
/// `reader_loop` shape) and a drain thread clears `server`. Returns
/// the wall time for `iters` frames **per writer**.
fn measure<R>(shared: &Shared, mut server: R, writers: usize, iters: u64, frame: &[u8]) -> Duration
where
    R: Read + Send + 'static,
{
    let stop = Arc::new(AtomicBool::new(false));

    // Server-side drain: keeps the client's send buffer empty so
    // writer latency reflects mutex contention, not TCP backpressure.
    let drain_stop = stop.clone();
    let drain = thread::spawn(move || {
        let mut buf = vec![0u8; 1 << 16].into_boxed_slice();
        while !drain_stop.load(Ordering::Relaxed) {
            match server.read(&mut buf) {
                Ok(0) => break,
                Ok(_) => {}
                // Read timeout — poll the stop flag and retry. The
                // caller configures the timeout on the server socket.
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut => {}
                Err(_) => break,
            }
        }
    });

    // Client reader — the production shape: a blocking `poll` under
    // the shared mutex up to the socket's read timeout, then a 1 ms
    // yield so writers get a window.
    let mut reader = shared.clone();
    let reader_stop = stop.clone();
    let rd = thread::spawn(move || {
        let mut fr = FrameReader::new();
        while !reader_stop.load(Ordering::Relaxed) {
            match reader.read_frame(&mut fr, MAX_MSG) {
                Ok(None) => thread::sleep(READER_YIELD),
                Ok(Some(_)) => {}
                Err(_) => break,
            }
        }
    });

    // Timed region: `writers` threads each write `iters` frames.
    let start = Instant::now();
    thread::scope(|s| {
        for _ in 0..writers {
            let mut w = shared.clone();
            s.spawn(move || {
                for _ in 0..iters {
                    w.write_frame(frame).expect("write_frame in bench");
                }
            });
        }
    });
    let elapsed = start.elapsed();

    stop.store(true, Ordering::Relaxed);
    // The reader may be mid-poll — the join costs at most one read
    // timeout, outside the timed region.
    rd.join().expect("reader thread");
    drain.join().expect("drain thread");
    elapsed
}

/// One criterion row: `writers` concurrent `write_frame` callers on a
/// shared TLS stream vs. a plaintext TCP stream, under a reader that
/// polls with `poll_timeout` under the shared mutex.
fn contention_rows(c: &mut Criterion, name: &str, poll_timeout: Duration) {
    let (tls_a, tls_b) = bench_tls_configs();
    let mut g = c.benchmark_group(name);
    g.sample_size(20);
    for &(payload, writers) in &[(256_usize, 1), (256, 2), (256, 4), (1 << 14, 1), (1 << 14, 4)] {
        let frame = vec![0xAB_u8; payload];
        for transport in ["tls", "tcp"] {
            g.throughput(Throughput::Elements(u64::try_from(writers).expect("writers fits")));
            let id = format!("{transport}/{payload}B/w{writers}");
            g.bench_function(id, |b| {
                b.iter_custom(|iters| {
                    // The server end is boxed — `rustls` types stay
                    // unnameable from the bench crate, which has no
                    // rustls dep of its own.
                    let (shared, server): (Shared, Box<dyn Read + Send>) = if transport == "tls" {
                        let (client, server) = bench_tls_connect(&tls_a, &tls_b);
                        client.sock.set_read_timeout(Some(poll_timeout)).expect("read timeout");
                        client.sock.set_nodelay(true).expect("nodelay");
                        let boxed: Box<dyn IoStream> = Box::new(client);
                        (SharedStream::wrap(boxed), Box::new(server))
                    } else {
                        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
                        let addr = listener.local_addr().expect("addr");
                        let client = std::net::TcpStream::connect(addr).expect("connect");
                        let (server, _) = listener.accept().expect("accept");
                        client.set_read_timeout(Some(poll_timeout)).expect("read timeout");
                        client.set_nodelay(true).expect("nodelay");
                        server
                            .set_read_timeout(Some(Duration::from_millis(50)))
                            .expect("server read timeout");
                        let boxed: Box<dyn IoStream> = Box::new(client);
                        (SharedStream::wrap(boxed), Box::new(server))
                    };
                    measure(&shared, server, writers, iters, &frame)
                });
            });
        }
    }
    g.finish();
}

fn tls_contention(c: &mut Criterion) {
    // Fast rows at the scaled-down poll interval — the reader/writer
    // shape is identical to production; only the timeout differs.
    contention_rows(c, "shared_stream", BENCH_POLL);
    // Production-poll spot check: what a writer actually waits behind
    // a 500 ms blocking read under the shared mutex.
    contention_rows(c, "shared_stream_prod_poll", PROD_POLL);
}

criterion_group!(benches, tls_contention);
criterion_main!(benches);
