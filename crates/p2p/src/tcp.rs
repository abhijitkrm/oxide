//! Real TCP transport — length-prefixed framing over `std::net`.
//!
//! # What this is
//!
//! A production-shaped [`Transport`](ports::Transport) implementation
//! using `std::net::TcpStream` and background threads. Each node
//! listens on a TCP port, accepts connections from peers, and
//! exchanges length-prefixed frames. This replaces the in-process
//! `MeshTransport` for real multi-node devnet operation.
//!
//! # Why this exists
//!
//! The in-process mesh proves the `Transport` seam but doesn't
//! exercise real network I/O. The TCP transport validates that the
//! consensus and broadcast layers work over a real network stack:
//! real connections, real framing, real thread-per-peer I/O. It is
//! the bridge between the deterministic simulation and the eventual
//! commonware-p2p / libp2p adapter.
//!
//! # Framing
//!
//! Each message is framed as:
//! `[length: 4 bytes big-endian u32][payload: length bytes]`
//!
//! The 4-byte length prefix caps messages at ~4 GiB; the transport
//! enforces a configurable `max_message_bytes` below that.
//!
//! # Threading model
//!
//! Each `TcpTransport` owns:
//! - An `Arc<Mutex<HashMap<PeerId, TcpStream>>>` for outbound sends.
//! - A `crossbeam`/`std` channel for inbound messages (written by
//!   reader threads, read by `recv()`).
//! - A background accept thread that spawns a reader thread per
//!   incoming connection.
//!
//! # Phase 1 scope
//!
//! No TLS, no authentication, no encryption. The caps advertise
//! `authenticated = false`, `encrypted = false`. Phase 2 adds Noise
//! or TLS via the commonware-p2p adapter. This transport is for
//! local devnet only — do not use across untrusted networks.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::Duration;

use ports::transport::{InboundMessage, PeerId, Transport, TransportCaps, TransportError};

/// The default maximum message size for the TCP transport: 16 MiB.
/// Matches the mesh transport and the broadcast crate's
/// `ERASURE_MAX_BYTES`.
const DEFAULT_MAX_MESSAGE_BYTES: u64 = 16 << 20;

/// The default connect timeout for outbound TCP connections. Short
/// enough that a dead peer is detected quickly during devnet startup.
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// The default read timeout for reader threads. This is a safety net
/// — normally the reader blocks indefinitely on `read_exact`. The
/// timeout prevents a stalled connection from holding a thread
/// forever. Set to 30s; if no data arrives in 30s, the reader
/// assumes the connection is dead and exits.
const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Configuration for a [`TcpTransport`] instance.
///
/// All values that were previously hardcoded as `const` are now
/// fields on this struct. Loaded from the [`config`](::config) crate's
/// [`NetworkConfig`](::config::NetworkConfig).
#[derive(Debug, Clone)]
pub struct TcpTransportConfig {
    /// The maximum message size the transport accepts, in bytes.
    /// Messages larger than this are rejected with
    /// [`TransportError::MessageTooLarge`].
    pub max_message_bytes: u64,

    /// The connect timeout for outbound TCP connections.
    pub connect_timeout: Duration,

    /// The read timeout for reader threads.
    pub read_timeout: Duration,
}

impl Default for TcpTransportConfig {
    fn default() -> Self {
        Self {
            max_message_bytes: DEFAULT_MAX_MESSAGE_BYTES,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            read_timeout: DEFAULT_READ_TIMEOUT,
        }
    }
}

/// A peer's TCP address (host:port).
pub type TcpAddr = String;

/// A TCP transport: real network I/O over `std::net`.
///
/// Each transport instance:
/// 1. Listens on a TCP port for incoming connections.
/// 2. Connects to a set of peer addresses.
/// 3. Exchanges length-prefixed frames with peers.
/// 4. Queues inbound messages in a channel for `recv()`.
///
/// # Threading
///
/// The transport spawns:
/// - One accept thread (listens for new connections).
/// - One reader thread per accepted/connected peer.
///
/// All threads are detached — the transport lives for the process
/// lifetime. There is no graceful shutdown in v0; Phase 2 adds
/// `close()`.
pub struct TcpTransport {
    /// Outbound connections: peer ID → TCP stream. Behind `Mutex`
    /// because `send()` takes `&mut self` but the accept thread may
    /// insert new connections concurrently.
    streams: Arc<Mutex<HashMap<PeerId, TcpStream>>>,
    /// Inbound message channel. Reader threads write; `recv()`
    /// reads.
    inbound_rx: Mutex<mpsc::Receiver<InboundMessage>>,
    /// This node's peer ID.
    peer_id: PeerId,
    /// The transport configuration (max message size, timeouts).
    config: TcpTransportConfig,
}

impl TcpTransport {
    /// Construct a TCP transport for a node with default config.
    ///
    /// # Arguments
    ///
    /// - `listen_addr`: the address to listen on (e.g. "127.0.0.1:9000").
    /// - `peer_id`: this node's peer ID.
    /// - `peers`: a list of `(peer_id, addr)` tuples for peers to
    ///   connect to. The transport connects to each peer in the
    ///   background. Incoming connections from unknown peers are
    ///   also accepted (the peer ID is sent as the first message
    ///   on each connection).
    ///
    /// # Panics
    ///
    /// Panics if the listen address cannot be bound.
    pub fn new(listen_addr: &str, peer_id: PeerId, peers: Vec<(PeerId, TcpAddr)>) -> Self {
        Self::with_config(listen_addr, peer_id, peers, TcpTransportConfig::default())
    }

    /// Construct a TCP transport for a node with explicit config.
    ///
    /// Use this constructor when you need to override the default
    /// timeouts or max message size (e.g. from a TOML config file via
    /// the [`config`](::config) crate).
    ///
    /// # Arguments
    ///
    /// - `listen_addr`: the address to listen on (e.g. "127.0.0.1:9000").
    /// - `peer_id`: this node's peer ID.
    /// - `peers`: a list of `(peer_id, addr)` tuples for peers to
    ///   connect to.
    /// - `config`: the transport configuration (timeouts, max message
    ///   size).
    ///
    /// # Panics
    ///
    /// Panics if the listen address cannot be bound.
    pub fn with_config(
        listen_addr: &str,
        peer_id: PeerId,
        peers: Vec<(PeerId, TcpAddr)>,
        config: TcpTransportConfig,
    ) -> Self {
        let listener = TcpListener::bind(listen_addr)
            .unwrap_or_else(|e| panic!("failed to bind TCP transport to {listen_addr}: {e}"));

        let streams: Arc<Mutex<HashMap<PeerId, TcpStream>>> = Arc::new(Mutex::new(HashMap::new()));
        let (inbound_tx, inbound_rx) = mpsc::channel::<InboundMessage>();

        let max_message_bytes = config.max_message_bytes;
        let connect_timeout = config.connect_timeout;
        let read_timeout = config.read_timeout;

        // Spawn the accept thread: accepts incoming connections,
        // reads the peer's ID (first frame), and spawns a reader
        // thread for each connection.
        let accept_streams = streams.clone();
        let accept_tx = inbound_tx.clone();
        thread::spawn(move || {
            for stream_result in listener.incoming() {
                let Ok(mut stream) = stream_result else {
                    continue; // accept error — try next
                };
                // Read the peer's ID as the first frame.
                let Ok(peer_id) = read_frame(&mut stream, max_message_bytes) else {
                    continue; // connection closed before ID
                };
                // Set read timeout for the reader thread.
                let _ = stream.set_read_timeout(Some(read_timeout));
                // Register the stream for outbound sends.
                accept_streams.lock().unwrap().insert(peer_id.clone(), stream.try_clone().unwrap());
                // Spawn a reader thread for this connection.
                let tx = accept_tx.clone();
                thread::spawn(move || {
                    reader_loop(stream, peer_id, tx, max_message_bytes);
                });
            }
        });

        // Connect to each peer in the background. Each connection
        // sends our peer ID as the first frame, then enters the
        // reader loop.
        let connect_streams = streams.clone();
        let connect_tx = inbound_tx.clone();
        let our_id = peer_id.clone();
        thread::spawn(move || {
            for (peer_id, addr) in peers {
                let pid = peer_id.clone();
                let oid = our_id.clone();
                let cs = connect_streams.clone();
                let ct = connect_tx.clone();
                thread::spawn(move || {
                    // Retry connection — the peer may not be
                    // listening yet (devnet startup race).
                    let stream = loop {
                        if let Ok(s) = TcpStream::connect_timeout(
                            &addr.parse().unwrap_or_else(|_| panic!("invalid TCP address: {addr}")),
                            connect_timeout,
                        ) {
                            break s;
                        }
                        thread::sleep(Duration::from_millis(100));
                    };
                    let mut stream = stream;
                    // Send our peer ID as the first frame.
                    if write_frame(&mut stream, &oid).is_err() {
                        return; // connection failed
                    }
                    let _ = stream.set_read_timeout(Some(read_timeout));
                    // Register the stream for outbound sends.
                    cs.lock().unwrap().insert(pid.clone(), stream.try_clone().unwrap());
                    // Reader loop for this connection.
                    reader_loop(stream, pid, ct, max_message_bytes);
                });
            }
        });

        Self { streams, inbound_rx: Mutex::new(inbound_rx), peer_id, config }
    }

    /// This node's peer ID.
    pub fn peer_id(&self) -> &PeerId {
        &self.peer_id
    }
}

impl Transport for TcpTransport {
    fn send(&mut self, peer: &PeerId, bytes: &[u8]) -> Result<(), TransportError> {
        if bytes.len() as u64 > self.config.max_message_bytes {
            return Err(TransportError::MessageTooLarge);
        }
        let mut streams = self.streams.lock().unwrap();
        let Some(stream) = streams.get_mut(peer) else {
            return Err(TransportError::UnknownPeer);
        };
        write_frame(stream, bytes).map_err(|_| TransportError::ChannelClosed)
    }

    fn recv(&mut self) -> Option<InboundMessage> {
        self.inbound_rx.lock().unwrap().try_recv().ok()
    }

    fn capabilities(&self) -> TransportCaps {
        TransportCaps {
            authenticated: false,
            encrypted: false,
            max_message_bytes: self.config.max_message_bytes,
        }
    }
}

/// Read a length-prefixed frame from a TCP stream.
///
/// Frame format: `[length: 4 bytes BE u32][payload: length bytes]`.
///
/// # Errors
///
/// Returns `Err` on I/O error, EOF, or if the frame exceeds
/// `max_message_bytes`.
fn read_frame(stream: &mut TcpStream, max_message_bytes: u64) -> Result<Vec<u8>, std::io::Error> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u64::from(u32::from_be_bytes(len_buf));
    if len > max_message_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "frame exceeds max message size",
        ));
    }
    let mut payload = vec![0u8; usize::try_from(len).unwrap_or(usize::MAX)];
    stream.read_exact(&mut payload)?;
    Ok(payload)
}

/// Write a length-prefixed frame to a TCP stream.
///
/// Frame format: `[length: 4 bytes BE u32][payload: length bytes]`.
fn write_frame(stream: &mut TcpStream, bytes: &[u8]) -> Result<(), std::io::Error> {
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(bytes)?;
    stream.flush()?;
    Ok(())
}

/// The reader loop: reads frames from a peer's stream and sends
/// them to the inbound channel. Exits when the stream is closed
/// or an error occurs.
fn reader_loop(
    mut stream: TcpStream,
    peer_id: PeerId,
    tx: mpsc::Sender<InboundMessage>,
    max_message_bytes: u64,
) {
    loop {
        match read_frame(&mut stream, max_message_bytes) {
            Ok(bytes) => {
                let msg = InboundMessage { from: peer_id.clone(), bytes };
                if tx.send(msg).is_err() {
                    return; // channel closed — transport shut down
                }
            }
            Err(_) => return, // connection closed or error
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Basic send/recv over TCP: two nodes exchange a message.
    #[test]
    fn tcp_basic_send_recv() {
        // Each node listens on its own port and connects to the
        // other. We use ephemeral ports (bind to :0) — but
        // `TcpTransport::new` needs a known address for peers to
        // connect to. So we bind a listener first to get the port,
        // then pass it to `TcpTransport::new`.
        //
        // Actually, `TcpTransport::new` binds internally. We need
        // to know the listen port before constructing the transport.
        // Use fixed ports on localhost for the test.
        let addr_a = "127.0.0.1:19010";
        let addr_b = "127.0.0.1:19011";
        let id_a = vec![0u8];
        let id_b = vec![1u8];

        let mut transport_a =
            TcpTransport::new(addr_a, id_a.clone(), vec![(id_b.clone(), addr_b.to_string())]);
        let mut transport_b =
            TcpTransport::new(addr_b, id_b.clone(), vec![(id_a.clone(), addr_a.to_string())]);

        // Give the connections time to establish.
        thread::sleep(Duration::from_millis(500));

        // A sends to B.
        transport_a.send(&id_b, b"hello from A").unwrap();

        // B receives from A.
        let msg = poll_recv(&mut transport_b, Duration::from_secs(5));
        let msg = msg.expect("B should receive from A");
        assert_eq!(msg.from, id_a);
        assert_eq!(msg.bytes, b"hello from A");

        // B sends to A.
        transport_b.send(&id_a, b"hello from B").unwrap();
        let msg = poll_recv(&mut transport_a, Duration::from_secs(5));
        let msg = msg.expect("A should receive from B");
        assert_eq!(msg.from, id_b);
        assert_eq!(msg.bytes, b"hello from B");
    }

    /// Multiple messages in FIFO order over TCP.
    #[test]
    fn tcp_fifo_order() {
        let addr_a = "127.0.0.1:19020";
        let addr_b = "127.0.0.1:19021";
        let id_a = vec![0u8];
        let id_b = vec![1u8];

        let mut transport_a =
            TcpTransport::new(addr_a, id_a.clone(), vec![(id_b.clone(), addr_b.to_string())]);
        let mut transport_b =
            TcpTransport::new(addr_b, id_b.clone(), vec![(id_a.clone(), addr_a.to_string())]);

        thread::sleep(Duration::from_millis(500));

        // A sends 10 messages to B.
        for i in 0..10u8 {
            transport_a.send(&id_b, &[i]).unwrap();
        }

        // B receives all 10 in order.
        for i in 0..10u8 {
            let msg = poll_recv(&mut transport_b, Duration::from_secs(5));
            let msg = msg.expect("B should receive message");
            assert_eq!(msg.bytes, &[i]);
        }
    }

    /// Three-node mesh: A → B → C → A.
    #[test]
    fn tcp_three_node_mesh() {
        let addr_a = "127.0.0.1:19030";
        let addr_b = "127.0.0.1:19031";
        let addr_c = "127.0.0.1:19032";
        let id_a = vec![0u8];
        let id_b = vec![1u8];
        let id_c = vec![2u8];

        let mut ta = TcpTransport::new(
            addr_a,
            id_a.clone(),
            vec![(id_b.clone(), addr_b.to_string()), (id_c.clone(), addr_c.to_string())],
        );
        let mut tb = TcpTransport::new(
            addr_b,
            id_b.clone(),
            vec![(id_a.clone(), addr_a.to_string()), (id_c.clone(), addr_c.to_string())],
        );
        let mut tc = TcpTransport::new(
            addr_c,
            id_c.clone(),
            vec![(id_a.clone(), addr_a.to_string()), (id_b.clone(), addr_b.to_string())],
        );

        thread::sleep(Duration::from_millis(500));

        // A sends to B and C.
        ta.send(&id_b, b"A->B").unwrap();
        ta.send(&id_c, b"A->C").unwrap();

        // B receives from A.
        let msg = poll_recv(&mut tb, Duration::from_secs(5)).expect("B should receive from A");
        assert_eq!(msg.from, id_a);
        assert_eq!(msg.bytes, b"A->B");

        // C receives from A.
        let msg = poll_recv(&mut tc, Duration::from_secs(5)).expect("C should receive from A");
        assert_eq!(msg.from, id_a);
        assert_eq!(msg.bytes, b"A->C");

        // B sends to C.
        tb.send(&id_c, b"B->C").unwrap();
        let msg = poll_recv(&mut tc, Duration::from_secs(5)).expect("C should receive from B");
        assert_eq!(msg.from, id_b);
        assert_eq!(msg.bytes, b"B->C");
    }

    /// Unknown peer: sending to a non-existent peer fails.
    #[test]
    fn tcp_unknown_peer() {
        let addr = "127.0.0.1:19040";
        let id = vec![0u8];
        let mut transport = TcpTransport::new(addr, id, vec![]);
        let result = transport.send(&vec![99u8], b"hello");
        assert_eq!(result, Err(TransportError::UnknownPeer));
    }

    /// Message too large: sending a huge message fails.
    #[test]
    fn tcp_message_too_large() {
        let addr_a = "127.0.0.1:19050";
        let addr_b = "127.0.0.1:19051";
        let id_a = vec![0u8];
        let id_b = vec![1u8];

        let mut transport_a =
            TcpTransport::new(addr_a, id_a.clone(), vec![(id_b.clone(), addr_b.to_string())]);
        let _transport_b =
            TcpTransport::new(addr_b, id_b.clone(), vec![(id_a.clone(), addr_a.to_string())]);

        thread::sleep(Duration::from_millis(500));

        let huge = vec![0u8; usize::try_from(DEFAULT_MAX_MESSAGE_BYTES + 1).unwrap_or(usize::MAX)];
        let result = transport_a.send(&id_b, &huge);
        assert_eq!(result, Err(TransportError::MessageTooLarge));
    }

    /// Poll `recv()` with a timeout. Returns `None` if no message
    /// arrives within the timeout.
    fn poll_recv(transport: &mut TcpTransport, timeout: Duration) -> Option<InboundMessage> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if let Some(msg) = transport.recv() {
                return Some(msg);
            }
            if std::time::Instant::now() > deadline {
                return None;
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    /// The `with_config` constructor respects custom max message size.
    #[test]
    fn tcp_with_config_custom_max_message_bytes() {
        let addr_a = "127.0.0.1:19060";
        let addr_b = "127.0.0.1:19061";
        let id_a = vec![0u8];
        let id_b = vec![1u8];

        let custom_config = TcpTransportConfig {
            max_message_bytes: 1024, // 1 KiB — very small for testing
            connect_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(30),
        };

        let mut transport_a = TcpTransport::with_config(
            addr_a,
            id_a.clone(),
            vec![(id_b.clone(), addr_b.to_string())],
            custom_config,
        );
        let _transport_b =
            TcpTransport::new(addr_b, id_b.clone(), vec![(id_a.clone(), addr_a.to_string())]);

        thread::sleep(Duration::from_millis(500));

        // A small message (100 bytes) fits under the 1 KiB limit.
        let small = vec![0u8; 100];
        assert!(transport_a.send(&id_b, &small).is_ok());

        // A large message (2 KiB) exceeds the 1 KiB limit.
        let large = vec![0u8; 2048];
        assert_eq!(transport_a.send(&id_b, &large), Err(TransportError::MessageTooLarge));

        // Capabilities reflect the custom limit.
        let caps = transport_a.capabilities();
        assert_eq!(caps.max_message_bytes, 1024);
    }
}
