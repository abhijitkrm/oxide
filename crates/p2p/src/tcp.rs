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
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::Duration;

use ports::transport::{InboundMessage, PeerId, Transport, TransportCaps, TransportError};

#[cfg(feature = "tls")]
use crate::tls::TlsConfig;

/// A trait that abstracts over plain TCP and TLS streams.
///
/// Both `TcpStream` and `SharedStream<rustls::StreamOwned<...>>`
/// implement this trait, allowing the transport to store either
/// type in the same `HashMap`.
///
/// This is not a hot-path type — connections are established once at
/// startup, not per message. The dynamic dispatch cost is negligible.
///
/// The trait provides `read_frame` and `write_frame` methods directly
/// (instead of extending `Read + Write`) because Rust does not
/// support trait upcasting from `dyn PeerStream` to `dyn Read` or
/// `dyn Write` on stable. Putting the frame methods on the trait
/// avoids the upcasting issue entirely.
pub trait PeerStream: Send {
    /// Read a length-prefixed frame from the stream.
    ///
    /// # Errors
    ///
    /// Returns `Err` on I/O error, EOF, timeout, or if the frame
    /// exceeds `max_message_bytes`.
    fn read_frame(&mut self, max_message_bytes: u64) -> io::Result<Vec<u8>>;

    /// Write a length-prefixed frame to the stream.
    ///
    /// # Errors
    ///
    /// Returns `Err` on I/O error.
    fn write_frame(&mut self, bytes: &[u8]) -> io::Result<()>;
}

impl PeerStream for TcpStream {
    fn read_frame(&mut self, max_message_bytes: u64) -> io::Result<Vec<u8>> {
        read_frame(self, max_message_bytes)
    }

    fn write_frame(&mut self, bytes: &[u8]) -> io::Result<()> {
        write_frame(self, bytes)
    }
}

/// A shared, thread-safe wrapper around a stream type.
///
/// Used for TLS streams, which cannot be `try_clone()`d like
/// `TcpStream`. The underlying stream is behind an `Arc<Mutex<...>>`,
/// so both the reader thread and the send path can access it.
///
/// # Lock discipline
///
/// The reader thread sets a short read timeout (via the stream's
/// `set_read_timeout`) before each `read_frame` call, so the mutex
/// is not held indefinitely. The writer (send path) acquires the
/// lock only for the duration of a `write_frame` call.
#[cfg(feature = "tls")]
struct SharedStream<S: Read + Write + Send> {
    inner: Arc<Mutex<S>>,
}

#[cfg(feature = "tls")]
impl<S: Read + Write + Send> Clone for SharedStream<S> {
    fn clone(&self) -> Self {
        Self { inner: Arc::clone(&self.inner) }
    }
}

#[cfg(feature = "tls")]
impl<S: Read + Write + Send> Read for SharedStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.lock().unwrap().read(buf)
    }
}

#[cfg(feature = "tls")]
impl<S: Read + Write + Send> Write for SharedStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.lock().unwrap().write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.lock().unwrap().flush()
    }
}

#[cfg(feature = "tls")]
impl<S: Read + Write + Send> PeerStream for SharedStream<S> {
    fn read_frame(&mut self, max_message_bytes: u64) -> io::Result<Vec<u8>> {
        let mut stream = self.inner.lock().unwrap();
        read_frame(&mut *stream, max_message_bytes)
    }

    fn write_frame(&mut self, bytes: &[u8]) -> io::Result<()> {
        let mut stream = self.inner.lock().unwrap();
        write_frame(&mut *stream, bytes)
    }
}

/// The read timeout used by TLS reader threads. Short enough that
/// the writer can acquire the lock between read attempts, long
/// enough that idle connections don't busy-poll.
#[cfg(feature = "tls")]
const TLS_READER_POLL_TIMEOUT: Duration = Duration::from_millis(500);

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
/// lifetime. Call [`shutdown`](TcpTransport::shutdown) to gracefully
/// close all connections and stop the accept thread.
pub struct TcpTransport {
    /// Outbound send channels: peer ID → channel sender.
    ///
    /// Each peer has a dedicated writer thread that owns the write
    /// side of the stream. `send()` pushes bytes into the channel
    /// (O(1), no I/O under the lock), and the writer thread drains
    /// the channel and writes to the stream. This eliminates the
    /// global send mutex — a slow peer no longer blocks sends to
    /// other peers.
    ///
    /// Behind `Mutex` because `send()` takes `&mut self` but the
    /// accept thread may insert new connections concurrently. The
    /// lock is held only to look up the channel sender, not during
    /// I/O.
    streams: Arc<Mutex<HashMap<PeerId, mpsc::Sender<Vec<u8>>>>>,
    /// Inbound message channel. Reader threads write; `recv()`
    /// reads.
    inbound_rx: Mutex<mpsc::Receiver<InboundMessage>>,
    /// Inbound message channel sender. Stored so `add_peer` can
    /// spawn new reader threads that write to the same channel.
    inbound_tx: mpsc::Sender<InboundMessage>,
    /// This node's peer ID.
    peer_id: PeerId,
    /// The transport configuration (max message size, timeouts).
    config: TcpTransportConfig,
    /// Shutdown flag. When set, the accept thread stops accepting
    /// and reader threads exit. Set by [`shutdown`](Self::shutdown).
    shutdown: Arc<AtomicBool>,
    /// The TCP listener. Stored so we can close it on shutdown
    /// (dropping a `TcpListener` unblocks `incoming()`). Currently
    /// moved into the accept thread, so this is always `None`.
    #[allow(dead_code)]
    listener: Option<TcpListener>,
    /// TLS configuration, if TLS is enabled. `None` for plain TCP.
    #[cfg(feature = "tls")]
    tls: Option<Arc<TlsConfig>>,
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
        #[cfg(feature = "tls")]
        {
            Self::build(listen_addr, peer_id, peers, config, None)
        }
        #[cfg(not(feature = "tls"))]
        {
            Self::build(listen_addr, peer_id, peers, config)
        }
    }

    /// Construct a TCP transport with TLS encryption.
    ///
    /// When TLS is enabled, all peer connections are encrypted and
    /// authenticated via X.509 certificates. See [`TlsConfig`] for
    /// certificate management.
    ///
    /// # Arguments
    ///
    /// Same as [`with_config`](Self::with_config), plus:
    /// - `tls`: the TLS configuration (server + client configs).
    ///
    /// # Panics
    ///
    /// Panics if the listen address cannot be bound.
    #[cfg(feature = "tls")]
    pub fn with_tls(
        listen_addr: &str,
        peer_id: PeerId,
        peers: Vec<(PeerId, TcpAddr)>,
        config: TcpTransportConfig,
        tls: TlsConfig,
    ) -> Self {
        Self::build(listen_addr, peer_id, peers, config, Some(Arc::new(tls)))
    }

    /// Internal constructor shared by `with_config` and `with_tls`.
    #[allow(clippy::too_many_lines)]
    fn build(
        listen_addr: &str,
        peer_id: PeerId,
        peers: Vec<(PeerId, TcpAddr)>,
        config: TcpTransportConfig,
        #[cfg(feature = "tls")] tls: Option<Arc<TlsConfig>>,
    ) -> Self {
        let listener = TcpListener::bind(listen_addr)
            .unwrap_or_else(|e| panic!("failed to bind TCP transport to {listen_addr}: {e}"));

        let streams: Arc<Mutex<HashMap<PeerId, mpsc::Sender<Vec<u8>>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let (inbound_tx, inbound_rx) = mpsc::channel::<InboundMessage>();
        let shutdown = Arc::new(AtomicBool::new(false));

        let max_message_bytes = config.max_message_bytes;
        let connect_timeout = config.connect_timeout;
        let read_timeout = config.read_timeout;

        // Set the listener to non-blocking mode so the accept thread
        // can periodically check the shutdown flag.
        listener.set_nonblocking(true).expect("set_nonblocking on listener must succeed");

        // Spawn the accept thread: accepts incoming connections in
        // non-blocking mode, checks the shutdown flag between polls.
        let accept_streams = streams.clone();
        let accept_tx = inbound_tx.clone();
        let accept_shutdown = shutdown.clone();
        #[cfg(feature = "tls")]
        let accept_tls = tls.clone();
        thread::spawn(move || {
            while !accept_shutdown.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        // Switch back to blocking mode for the stream.
                        let _ = stream.set_nonblocking(false);

                        // Read the peer's ID and produce two stream
                        // handles: one for the map (writes), one for
                        // the reader thread (reads).
                        #[cfg(feature = "tls")]
                        let result = if let Some(ref tls_config) = accept_tls {
                            accept_tls_connection(
                                stream,
                                tls_config,
                                max_message_bytes,
                                read_timeout,
                            )
                        } else {
                            accept_plain_connection(stream, max_message_bytes, read_timeout)
                        };
                        #[cfg(not(feature = "tls"))]
                        let result =
                            accept_plain_connection(stream, max_message_bytes, read_timeout);

                        let Some((peer_id, write_stream, reader_stream)) = result else {
                            continue; // connection closed before ID
                        };
                        // Spawn a writer thread and register its
                        // channel sender for outbound sends.
                        let writer_tx = spawn_writer(write_stream, &accept_shutdown);
                        accept_streams.lock().unwrap().insert(peer_id.clone(), writer_tx);
                        // Spawn a reader thread for this connection.
                        let tx = accept_tx.clone();
                        let reader_shutdown = accept_shutdown.clone();
                        thread::spawn(move || {
                            reader_loop(
                                reader_stream,
                                peer_id,
                                tx,
                                max_message_bytes,
                                reader_shutdown,
                            );
                        });
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(50));
                    }
                    Err(_) => {
                        thread::sleep(Duration::from_millis(50));
                    }
                }
            }
        });

        // Connect to each peer in the background. Each connection
        // sends our peer ID as the first frame, then enters the
        // reader loop.
        let connect_streams = streams.clone();
        let connect_tx = inbound_tx.clone();
        let connect_shutdown = shutdown.clone();
        let our_id = peer_id.clone();
        #[cfg(feature = "tls")]
        let connect_tls = tls.clone();
        thread::spawn(move || {
            for (peer_id, addr) in peers {
                if connect_shutdown.load(Ordering::Relaxed) {
                    return; // shutting down — don't start new connections
                }
                let pid = peer_id.clone();
                let oid = our_id.clone();
                let cs = connect_streams.clone();
                let ct = connect_tx.clone();
                let rshut = connect_shutdown.clone();
                #[cfg(feature = "tls")]
                let ctls = connect_tls.clone();
                thread::spawn(move || {
                    // Retry connection — the peer may not be
                    // listening yet (devnet startup race).
                    let stream = loop {
                        if rshut.load(Ordering::Relaxed) {
                            return; // shutting down
                        }
                        if let Ok(s) = TcpStream::connect_timeout(
                            &addr.parse().unwrap_or_else(|_| panic!("invalid TCP address: {addr}")),
                            connect_timeout,
                        ) {
                            break s;
                        }
                        thread::sleep(Duration::from_millis(100));
                    };
                    #[cfg(feature = "tls")]
                    {
                        if let Some(ref tls_config) = ctls {
                            // Initiate TLS as client.
                            let server_name = rustls::pki_types::ServerName::try_from("localhost")
                                .expect("localhost is a valid server name");
                            let client_conn = rustls::ClientConnection::new(
                                tls_config.client_config.clone(),
                                server_name,
                            )
                            .expect("client connection must be valid");
                            let mut tls_stream = rustls::StreamOwned::new(client_conn, stream);
                            // Send our peer ID as the first frame.
                            if write_frame(&mut tls_stream, &oid).is_err() {
                                return; // connection failed
                            }
                            let _ = tls_stream.sock.set_read_timeout(Some(TLS_READER_POLL_TIMEOUT));
                            // Wrap in SharedStream for shared access.
                            let shared = SharedStream { inner: Arc::new(Mutex::new(tls_stream)) };
                            let reader_stream = Box::new(shared.clone()) as Box<dyn PeerStream>;
                            let write_stream = Box::new(shared) as Box<dyn PeerStream>;
                            // Spawn a writer thread and register its
                            // channel sender for outbound sends.
                            let writer_tx = spawn_writer(write_stream, &rshut);
                            cs.lock().unwrap().insert(pid.clone(), writer_tx);
                            // Reader loop for this connection.
                            reader_loop(reader_stream, pid, ct, max_message_bytes, rshut);
                            return;
                        }
                    }
                    // Plain TCP path.
                    let mut stream = stream;
                    // Send our peer ID as the first frame.
                    if write_frame(&mut stream, &oid).is_err() {
                        return; // connection failed
                    }
                    let _ = stream.set_read_timeout(Some(read_timeout));
                    // Clone for the map; the reader keeps the original.
                    let write_stream = Box::new(stream.try_clone().unwrap()) as Box<dyn PeerStream>;
                    let reader_stream = Box::new(stream) as Box<dyn PeerStream>;
                    // Spawn a writer thread and register its
                    // channel sender for outbound sends.
                    let writer_tx = spawn_writer(write_stream, &rshut);
                    cs.lock().unwrap().insert(pid.clone(), writer_tx);
                    // Reader loop for this connection.
                    reader_loop(reader_stream, pid, ct, max_message_bytes, rshut);
                });
            }
        });

        Self {
            streams,
            inbound_rx: Mutex::new(inbound_rx),
            inbound_tx,
            peer_id,
            config,
            shutdown,
            listener: None, // listener moved into accept thread
            #[cfg(feature = "tls")]
            tls,
        }
    }

    /// This node's peer ID.
    pub fn peer_id(&self) -> &PeerId {
        &self.peer_id
    }

    /// Gracefully shut down the transport.
    ///
    /// Sets the shutdown flag, closes all peer connections, and
    /// signals the accept thread to stop. Reader threads will exit
    /// when their streams are closed or when they check the flag.
    ///
    /// After `shutdown()` is called, `send()` will return
    /// [`TransportError::ChannelClosed`] and `recv()` will return
    /// `None` once all buffered messages are drained.
    ///
    /// # Panics
    ///
    /// Panics if the streams mutex is poisoned (a reader thread
    /// panicked while holding the lock).
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
        // Close all streams — this causes reader threads to get
        // errors on their next read and exit.
        self.streams.lock().unwrap().clear();
    }

    /// Returns `true` if the transport has been shut down.
    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::Relaxed)
    }

    /// Dynamically add a peer to the transport.
    ///
    /// Spawns a background thread that connects to the peer and
    /// enters the reader loop, just like the statically configured
    /// peers. This is used by the discovery protocol to connect to
    /// newly discovered peers at runtime.
    ///
    /// Does nothing if the peer is already connected or if the
    /// transport is shutting down.
    ///
    /// # Panics
    ///
    /// Panics if the streams mutex is poisoned, or if the peer
    /// address is not a valid `SocketAddr`.
    pub fn add_peer(&self, peer_id: PeerId, addr: TcpAddr) {
        // Check if already connected.
        if self.streams.lock().unwrap().contains_key(&peer_id) {
            return;
        }
        if self.shutdown.load(Ordering::Relaxed) {
            return;
        }
        let connect_timeout = self.config.connect_timeout;
        let read_timeout = self.config.read_timeout;
        let max_message_bytes = self.config.max_message_bytes;
        let streams = self.streams.clone();
        let tx = self.inbound_tx.clone();
        let shutdown = self.shutdown.clone();
        let our_id = self.peer_id.clone();
        #[cfg(feature = "tls")]
        let tls = self.tls.clone();
        let pid = peer_id.clone();
        thread::spawn(move || {
            // Retry connection — the peer may not be listening yet.
            let stream = loop {
                if shutdown.load(Ordering::Relaxed) {
                    return;
                }
                if let Ok(s) = TcpStream::connect_timeout(
                    &addr.parse().unwrap_or_else(|_| panic!("invalid TCP address: {addr}")),
                    connect_timeout,
                ) {
                    break s;
                }
                thread::sleep(Duration::from_millis(100));
            };
            #[cfg(feature = "tls")]
            {
                if let Some(ref tls_config) = tls {
                    let server_name = rustls::pki_types::ServerName::try_from("localhost")
                        .expect("localhost is a valid server name");
                    let client_conn = rustls::ClientConnection::new(
                        tls_config.client_config.clone(),
                        server_name,
                    )
                    .expect("client connection must be valid");
                    let mut tls_stream = rustls::StreamOwned::new(client_conn, stream);
                    if write_frame(&mut tls_stream, &our_id).is_err() {
                        return;
                    }
                    let _ = tls_stream.sock.set_read_timeout(Some(TLS_READER_POLL_TIMEOUT));
                    let shared = SharedStream { inner: Arc::new(Mutex::new(tls_stream)) };
                    let reader_stream = Box::new(shared.clone()) as Box<dyn PeerStream>;
                    let write_stream = Box::new(shared) as Box<dyn PeerStream>;
                    let writer_tx = spawn_writer(write_stream, &shutdown);
                    streams.lock().unwrap().insert(pid.clone(), writer_tx);
                    reader_loop(reader_stream, pid, tx, max_message_bytes, shutdown);
                    return;
                }
            }
            let mut stream = stream;
            if write_frame(&mut stream, &our_id).is_err() {
                return;
            }
            let _ = stream.set_read_timeout(Some(read_timeout));
            let write_stream = Box::new(stream.try_clone().unwrap()) as Box<dyn PeerStream>;
            let reader_stream = Box::new(stream) as Box<dyn PeerStream>;
            let writer_tx = spawn_writer(write_stream, &shutdown);
            streams.lock().unwrap().insert(pid.clone(), writer_tx);
            reader_loop(reader_stream, pid, tx, max_message_bytes, shutdown);
        });
    }
}

impl Transport for TcpTransport {
    fn send(&mut self, peer: &PeerId, bytes: &[u8]) -> Result<(), TransportError> {
        if bytes.len() as u64 > self.config.max_message_bytes {
            return Err(TransportError::MessageTooLarge);
        }
        // Look up the per-peer send channel and send bytes into it.
        // The lock is held only for the lookup, not during I/O —
        // the writer thread handles the actual write asynchronously.
        let streams = self.streams.lock().unwrap();
        let Some(sender) = streams.get(peer) else {
            return Err(TransportError::UnknownPeer);
        };
        // Clone the bytes into a Vec for the channel. The writer
        // thread owns the stream and writes the frame.
        sender.send(bytes.to_vec()).map_err(|_| TransportError::ChannelClosed)
    }

    fn recv(&mut self) -> Option<InboundMessage> {
        self.inbound_rx.lock().unwrap().try_recv().ok()
    }

    fn capabilities(&self) -> TransportCaps {
        TransportCaps {
            #[cfg(feature = "tls")]
            authenticated: self.tls.is_some(),
            #[cfg(not(feature = "tls"))]
            authenticated: false,
            #[cfg(feature = "tls")]
            encrypted: self.tls.is_some(),
            #[cfg(not(feature = "tls"))]
            encrypted: false,
            max_message_bytes: self.config.max_message_bytes,
        }
    }
}

/// Read a length-prefixed frame from any readable stream.
///
/// Frame format: `[length: 4 bytes BE u32][payload: length bytes]`.
///
/// # Errors
///
/// Returns `Err` on I/O error, EOF, or if the frame exceeds
/// `max_message_bytes`.
fn read_frame<R: Read>(stream: &mut R, max_message_bytes: u64) -> Result<Vec<u8>, std::io::Error> {
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

/// Write a length-prefixed frame to any writable stream.
///
/// Frame format: `[length: 4 bytes BE u32][payload: length bytes]`.
fn write_frame<W: Write>(stream: &mut W, bytes: &[u8]) -> Result<(), std::io::Error> {
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(bytes)?;
    stream.flush()?;
    Ok(())
}

/// The reader loop: reads frames from a peer's stream and sends
/// them to the inbound channel. Exits when the stream is closed,
/// an error occurs, or the shutdown flag is set.
fn reader_loop(
    mut stream: Box<dyn PeerStream>,
    peer_id: PeerId,
    tx: mpsc::Sender<InboundMessage>,
    max_message_bytes: u64,
    shutdown: Arc<AtomicBool>,
) {
    loop {
        if shutdown.load(Ordering::Relaxed) {
            return; // shutting down
        }
        match stream.read_frame(max_message_bytes) {
            Ok(bytes) => {
                let msg = InboundMessage { from: peer_id.clone(), bytes };
                if tx.send(msg).is_err() {
                    return; // channel closed — transport shut down
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => {
                // Read timeout (TLS poll timeout) — loop will check
                // the shutdown flag and retry.
            }
            Err(_) => return, // connection closed or error
        }
    }
}

/// The writer loop: drains the outbound channel and writes frames
/// to the peer's stream. Exits when the channel is closed (the
/// `send()` side was dropped) or an I/O error occurs.
///
/// This decouples `send()` from I/O — the global `streams` mutex is
/// not held during writes. A slow peer only blocks its own writer
/// thread, not sends to other peers.
fn writer_loop(
    mut stream: Box<dyn PeerStream>,
    rx: mpsc::Receiver<Vec<u8>>,
    shutdown: Arc<AtomicBool>,
) {
    while !shutdown.load(Ordering::Relaxed) {
        // Use recv_timeout to avoid blocking forever, so we can
        // check the shutdown flag periodically.
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(bytes) => {
                if stream.write_frame(&bytes).is_err() {
                    return; // connection closed or error
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // No data — loop and check shutdown flag.
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return; // channel closed — transport shut down
            }
        }
    }
}

/// Spawn a writer thread for a peer and return the channel sender.
///
/// The writer thread owns the write stream and drains the channel.
/// The returned sender is stored in the `streams` map for `send()`
/// to use.
fn spawn_writer(
    write_stream: Box<dyn PeerStream>,
    shutdown: &Arc<AtomicBool>,
) -> mpsc::Sender<Vec<u8>> {
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    let shutdown = Arc::clone(shutdown);
    thread::spawn(move || {
        writer_loop(write_stream, rx, shutdown);
    });
    tx
}

/// The result of accepting a connection: the peer's ID, a write
/// stream (for the map), and a reader stream (for the reader thread).
type AcceptResult = Option<(PeerId, Box<dyn PeerStream>, Box<dyn PeerStream>)>;

/// Accept a plain TCP connection: read the peer's ID, clone the
/// stream for the map and the reader.
///
/// Returns `(peer_id, write_stream, reader_stream)` on success,
/// `None` if the peer ID couldn't be read.
fn accept_plain_connection(
    mut stream: TcpStream,
    max_message_bytes: u64,
    read_timeout: Duration,
) -> AcceptResult {
    let peer_id = read_frame(&mut stream, max_message_bytes).ok()?;
    let _ = stream.set_read_timeout(Some(read_timeout));
    let write_stream = Box::new(stream.try_clone().ok()?) as Box<dyn PeerStream>;
    let reader_stream = Box::new(stream) as Box<dyn PeerStream>;
    Some((peer_id, write_stream, reader_stream))
}

/// Accept a TLS connection: perform the TLS handshake, read the
/// peer's ID, and create shared stream handles for the map and
/// the reader.
///
/// Returns `(peer_id, write_stream, reader_stream)` on success,
/// `None` if the handshake or ID read fails.
#[cfg(feature = "tls")]
fn accept_tls_connection(
    stream: TcpStream,
    tls_config: &TlsConfig,
    max_message_bytes: u64,
    read_timeout: Duration,
) -> AcceptResult {
    let server_conn = rustls::ServerConnection::new(tls_config.server_config.clone()).ok()?;
    let mut tls_stream = rustls::StreamOwned::new(server_conn, stream);
    let _ = tls_stream.sock.set_read_timeout(Some(read_timeout));
    let peer_id = read_frame(&mut tls_stream, max_message_bytes).ok()?;
    let shared = SharedStream { inner: Arc::new(Mutex::new(tls_stream)) };
    let write_stream = Box::new(shared.clone()) as Box<dyn PeerStream>;
    let reader_stream = Box::new(shared) as Box<dyn PeerStream>;
    Some((peer_id, write_stream, reader_stream))
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

    /// Graceful shutdown: `shutdown()` closes connections and sets the flag.
    #[test]
    fn tcp_graceful_shutdown() {
        let addr_a = "127.0.0.1:19070";
        let addr_b = "127.0.0.1:19071";
        let id_a = vec![0u8];
        let id_b = vec![1u8];

        let mut transport_a =
            TcpTransport::new(addr_a, id_a.clone(), vec![(id_b.clone(), addr_b.to_string())]);
        let mut transport_b =
            TcpTransport::new(addr_b, id_b.clone(), vec![(id_a.clone(), addr_a.to_string())]);

        thread::sleep(Duration::from_millis(500));

        // Verify communication works before shutdown.
        transport_a.send(&id_b, b"before shutdown").unwrap();
        let msg = poll_recv(&mut transport_b, Duration::from_secs(5));
        assert!(msg.is_some(), "B should receive before shutdown");

        // Shut down A.
        transport_a.shutdown();
        assert!(transport_a.is_shutdown(), "A should be marked as shut down");

        // Sending after shutdown should fail (streams are cleared).
        let result = transport_a.send(&id_b, b"after shutdown");
        assert_eq!(result, Err(TransportError::UnknownPeer));

        // B should still work (only A was shut down).
        transport_b.send(&id_a, b"from B").ok(); // may fail if A closed the connection
    }

    /// Shutdown before connections are established: no panic.
    #[test]
    fn tcp_shutdown_before_connect() {
        let addr = "127.0.0.1:19080";
        let id = vec![0u8];
        let transport = TcpTransport::new(addr, id, vec![]);
        transport.shutdown();
        assert!(transport.is_shutdown());
    }
}
