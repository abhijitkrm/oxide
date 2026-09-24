//! TLS transport contention benchmark — audit001 §7.5's named
//! measurement, now gating the split halves.
//!
//! Oxide's TCP transport writes to a `try_clone()`d socket, so a slow
//! reader never blocks a writer. TLS gets the same shape by splitting
//! `rustls::StreamOwned` after the handshake into `TlsReadHalf` /
//! `TlsWriteHalf`: the reader polls `TLS_READER_POLL_TIMEOUT` (500 ms)
//! on its own socket handle with no lock held; writers serialize
//! encrypt→socket under a `wire` mutex (record sequence order) plus a
//! µs-scale `conn` crypto lock. This bench measures writer frame
//! latency while the reader is blocked in its poll, for the real mTLS
//! crypto path and a plaintext `TcpStream` baseline — the split should
//! sit near baseline, and it does (~4 µs vs ~3.4 µs solo).
//!
//! Informational only — no hard gate. The numbers answer the audit's
//! question "is the TLS stream discipline a live bottleneck under HFT
//! load?", not a per-release regression bound.

#![allow(missing_docs)]

use std::io::Read;
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use p2p::tcp::{FrameReader, PeerStream, bench_tls_configs, bench_tls_connect, bench_tls_split};

/// Matches `DEFAULT_MAX_MESSAGE_BYTES` in `tcp.rs` — frame decode
/// limit, not exercised by these payload sizes.
const MAX_MSG: u64 = 16 << 20;

/// Scaled-down stand-in for `TLS_READER_POLL_TIMEOUT` (500 ms) used by
/// the thread-scaling rows: the `p500` rows run the production value
/// so the report carries the true number too.
const BENCH_POLL: Duration = Duration::from_millis(20);
const PROD_POLL: Duration = Duration::from_millis(500);

/// Drive `writers` concurrent `write_frame` threads produced by
/// `make_writer` while `reader` polls its own socket — the production
/// `reader_loop` shape after the read/write split: no shared lock is
/// ever held across a socket syscall. A drain thread clears `server`.
/// Returns the wall time for `iters` frames **per writer**.
fn measure<R>(
    mut reader: Box<dyn PeerStream>,
    make_writer: &dyn Fn() -> Box<dyn PeerStream>,
    mut server: R,
    writers: usize,
    iters: u64,
    frame: &[u8],
) -> Duration
where
    R: Read + Send + 'static,
{
    let stop = Arc::new(AtomicBool::new(false));

    // Server-side drain: keeps the client's send buffer empty so
    // writer latency reflects crypto-lock contention, not TCP
    // backpressure.
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

    // Client reader — the production shape: poll the read half; its
    // blocking socket read holds no lock the writer needs.
    let reader_stop = stop.clone();
    let rd = thread::spawn(move || {
        let mut fr = FrameReader::new();
        while !reader_stop.load(Ordering::Relaxed) {
            match reader.read_frame(&mut fr, MAX_MSG) {
                Ok(_) => {}
                Err(_) => break,
            }
        }
    });

    // Timed region: `writers` threads each write `iters` frames.
    let start = Instant::now();
    thread::scope(|s| {
        for _ in 0..writers {
            let mut w = make_writer();
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

/// The pieces a `measure` call needs: the read half to poll, a factory
/// for per-writer clones of the write half, and the server end to
/// drain. Boxed so TLS types stay unnameable from this crate.
type SplitEnds = (Box<dyn PeerStream>, Box<dyn Fn() -> Box<dyn PeerStream>>, Box<dyn Read + Send>);

/// One criterion row: `writers` concurrent `write_frame` callers on
/// the split TLS halves vs. `try_clone`d plaintext TCP streams (the
/// baseline the split is meant to reach), while the reader polls
/// with `poll_timeout` on its own socket.
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
                    // `(reader, make_writer, server)` — halves are the
                    // production split for TLS; `try_clone`d sockets are
                    // the same shape for TCP.
                    let (reader, write_half, server): SplitEnds = if transport == "tls" {
                        let (client, server) = bench_tls_connect(&tls_a, &tls_b);
                        client.sock.set_read_timeout(Some(poll_timeout)).expect("read timeout");
                        client.sock.set_nodelay(true).expect("nodelay");
                        let (w, r) = bench_tls_split(client);
                        (
                            Box::new(r) as Box<dyn PeerStream>,
                            Box::new(move || Box::new(w.try_clone()) as Box<dyn PeerStream>),
                            Box::new(server) as Box<dyn Read + Send>,
                        )
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
                        let write_sock = client.try_clone().expect("tcp write clone");
                        (
                            Box::new(client) as Box<dyn PeerStream>,
                            Box::new(move || {
                                Box::new(write_sock.try_clone().expect("tcp writer clone"))
                                    as Box<dyn PeerStream>
                            }),
                            Box::new(server) as Box<dyn Read + Send>,
                        )
                    };
                    measure(reader, &write_half, server, writers, iters, &frame)
                });
            });
        }
    }
    g.finish();
}

fn tls_contention(c: &mut Criterion) {
    // Fast rows at the scaled-down poll interval — the reader/writer
    // shape is identical to production; only the timeout differs.
    contention_rows(c, "tls_split", BENCH_POLL);
    // Production-poll spot check: writer latency with the reader
    // blocked in the production 500 ms socket poll.
    contention_rows(c, "tls_split_prod_poll", PROD_POLL);
}

criterion_group!(benches, tls_contention);
criterion_main!(benches);
