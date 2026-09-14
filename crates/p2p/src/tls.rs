//! TLS configuration for the TCP transport.
//!
//! # What this is
//!
//! Provides TLS encryption and peer authentication for the TCP
//! transport. When TLS is enabled, all peer connections are
//! encrypted and the peer's identity is verified via X.509
//! certificates.
//!
//! # Why this exists
//!
//! Plain TCP is sufficient for local devnet but not for production:
//! - No encryption (anyone on the network can read consensus messages)
//! - No authentication (anyone can impersonate a peer)
//! - No integrity (a MITM can modify messages in transit)
//!
//! TLS solves all three. This module provides the configuration for
//! the `rustls` TLS implementation.
//!
//! # Devnet vs production
//!
//! For devnet/testnet, use [`TlsConfig::self_signed`] to generate a
//! self-signed certificate at startup. For production, use
//! [`TlsConfig::from_files`] to load certificates from files (the
//! certificates are managed by the deploy tooling).
//!
//! # Mutual TLS (C4 fix)
//!
//! The server requires and verifies client certificates (mTLS). The
//! peer's identity is extracted from the verified client certificate,
//! not from a self-claimed first-frame peer ID. This binds the peer
//! identity to the certificate's private key — impersonation is
//! impossible without the peer's private key.
//!
//! Each node has a certificate with a subject CN (Common Name) that
//! matches its peer ID. When a peer connects, its client certificate
//! is verified against the trust store, and the peer ID is looked up
//! from a `peer_id_map` that maps cert DER → peer ID. The first-frame
//! peer ID is verified against the certificate peer ID (defense in
//! depth).

use std::collections::HashMap;
use std::sync::Arc;

/// TLS configuration for a TCP transport node.
///
/// Contains the server config (for accepting TLS connections) and
/// the client config (for initiating TLS connections). Both are
/// `Arc`-shared because rustls configs are cheap to clone (they're
/// internally `Arc`-wrapped).
#[cfg(feature = "tls")]
pub struct TlsConfig {
    /// The server config (for accepting TLS connections from peers).
    /// Configured with `with_client_cert_verifier()` — requires
    /// client certificates (mTLS).
    pub server_config: Arc<rustls::ServerConfig>,
    /// The client config (for initiating TLS connections to peers).
    /// Configured with `with_client_auth_cert()` — presents our
    /// certificate to the server.
    pub client_config: Arc<rustls::ClientConfig>,
    /// C4 fix: our own certificate DER. Other nodes must trust this
    /// cert to verify our identity during mTLS handshake. Exposed
    /// so callers can share it with peers before connecting.
    pub cert_der: Vec<u8>,
    /// C4 fix: maps client cert DER bytes → peer ID. Used to
    /// authenticate the peer's identity from the verified client
    /// certificate, eliminating reliance on the self-claimed
    /// first-frame peer ID.
    peer_id_map: HashMap<Vec<u8>, Vec<u8>>,
}

#[cfg(feature = "tls")]
impl TlsConfig {
    /// Generate a self-signed TLS config for devnet/testnet with
    /// mutual TLS (C4 fix).
    ///
    /// Creates a self-signed X.509 certificate with the given peer
    /// ID as the subject CN. The certificate is trusted by all peers
    /// that have it in their trust store.
    ///
    /// For a multi-node devnet, call this for each node and share the
    /// certificates so each node trusts the others.
    ///
    /// # Arguments
    ///
    /// - `peer_id`: this node's peer ID (used as the certificate CN).
    /// - `trusted_peers`: list of `(peer_id, cert_der)` pairs for all
    ///   peers that this node should trust. The cert DER is used both
    ///   for the trust store and for the `peer_id_map`.
    ///
    /// # Panics
    ///
    /// Panics if certificate generation fails (should not happen with
    /// valid parameters).
    pub fn self_signed(peer_id: &[u8], trusted_peers: Vec<(Vec<u8>, Vec<u8>)>) -> Self {
        // C4 fix: generate a self-signed end-entity cert. The same
        // cert serves as both the TLS cert (for the handshake) and
        // the trust anchor (in the root store). We use PEM
        // serialization and parse with `rustls_pemfile` for maximum
        // compatibility with rustls's cert loading pipeline.
        let (cert_pem, key_pem) = generate_ca_cert_pem(peer_id);
        Self::with_cert_pem(peer_id, &cert_pem, &key_pem, trusted_peers)
    }

    /// Create a TLS config from pre-generated PEM-encoded cert and
    /// key. This allows multiple nodes to share pre-generated certs
    /// so node A can trust node B's actual cert (not a separately
    /// generated one).
    ///
    /// # Panics
    ///
    /// Panics if certificate parsing fails (should not happen with
    /// valid PEM input).
    pub fn with_cert_pem(
        peer_id: &[u8],
        cert_pem: &str,
        key_pem: &str,
        trusted_peers: Vec<(Vec<u8>, Vec<u8>)>,
    ) -> Self {
        // Parse the cert and key from PEM.
        let cert_der = rustls_pemfile::certs(&mut cert_pem.as_bytes())
            .next()
            .expect("at least one cert in PEM")
            .expect("cert PEM must be valid");
        let key_der = rustls_pemfile::private_key(&mut key_pem.as_bytes())
            .expect("key PEM must be valid")
            .expect("at least one key in PEM");

        // Serialize cert_der to Vec for the peer_id_map.
        let cert_der_vec = cert_der.as_ref().to_vec();

        // Build the peer_id_map: cert DER → peer ID.
        let mut peer_id_map: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
        peer_id_map.insert(cert_der_vec.clone(), peer_id.to_vec());
        for (pid, cert) in &trusted_peers {
            peer_id_map.insert(cert.clone(), pid.clone());
        }

        // Build the root cert store for the server's client cert
        // verifier. The server verifies client certificates against
        // this trust store. Each self-signed cert is its own CA.
        let mut server_root_store = rustls::RootCertStore::empty();
        for (_, cert) in &trusted_peers {
            server_root_store
                .add(rustls::pki_types::CertificateDer::from(cert.clone()))
                .expect("peer cert must be valid");
        }
        // Also trust our own cert (for self-connection testing).
        server_root_store.add(cert_der.clone()).expect("self cert must be valid");

        // C4 fix: server config requires client certificates (mTLS).
        // The WebPkiClientVerifier verifies the client cert chain
        // against the root store. Without a valid client cert, the
        // TLS handshake fails.
        let client_verifier =
            rustls::server::WebPkiClientVerifier::builder(Arc::new(server_root_store))
                .build()
                .expect("client cert verifier must be valid");

        let server_cert = cert_der.clone();
        let server_key = key_der.clone_key();
        let server_config = rustls::ServerConfig::builder()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(vec![server_cert], server_key)
            .expect("server config must be valid");
        let server_config = Arc::new(server_config);

        // Build the client root cert store (same as server's).
        let mut client_root_store = rustls::RootCertStore::empty();
        for (_, cert) in &trusted_peers {
            client_root_store
                .add(rustls::pki_types::CertificateDer::from(cert.clone()))
                .expect("peer cert must be valid");
        }
        client_root_store.add(cert_der.clone()).expect("self cert must be valid");

        // C4 fix: client config presents our certificate to the
        // server (mTLS). The server verifies it against its trust
        // store.
        let client_cert = cert_der.clone();
        let client_key = key_der;
        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(client_root_store)
            .with_client_auth_cert(vec![client_cert], client_key)
            .expect("client config must be valid");
        let client_config = Arc::new(client_config);

        Self { server_config, client_config, cert_der: cert_der_vec, peer_id_map }
    }

    /// Load TLS config from PEM-encoded certificate and key files
    /// with mutual TLS (C4 fix).
    ///
    /// For production, certificates are managed by the deploy tooling
    /// and loaded from files at startup.
    ///
    /// # Arguments
    ///
    /// - `cert_path`: path to the PEM-encoded certificate file.
    /// - `key_path`: path to the PEM-encoded private key file.
    /// - `trusted_peers`: list of `(peer_id, cert_path)` pairs for
    ///   all trusted peers.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the files cannot be read or parsed.
    pub fn from_files(
        cert_path: &str,
        key_path: &str,
        trusted_peers: &[(Vec<u8>, &str)],
    ) -> Result<Self, TlsConfigError> {
        // Load the server certificate.
        let cert_pem = std::fs::read(cert_path)
            .map_err(|e| TlsConfigError::FileRead(cert_path.to_string(), e.to_string()))?;
        let cert_der = rustls_pemfile::certs(&mut cert_pem.as_slice())
            .next()
            .ok_or_else(|| TlsConfigError::Parse("no certificate in PEM".to_string()))?
            .map_err(|e| TlsConfigError::Parse(e.to_string()))?;

        // Load the server private key.
        let key_pem = std::fs::read(key_path)
            .map_err(|e| TlsConfigError::FileRead(key_path.to_string(), e.to_string()))?;
        let key_der = rustls_pemfile::private_key(&mut key_pem.as_slice())
            .map_err(|e| TlsConfigError::Parse(e.to_string()))?
            .ok_or_else(|| TlsConfigError::Parse("no private key in PEM".to_string()))?;

        // Load trusted peer certs and build the peer_id_map.
        let mut peer_id_map: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
        let mut root_store = rustls::RootCertStore::empty();
        for (peer_id, peer_cert_path) in trusted_peers {
            let peer_pem = std::fs::read(peer_cert_path)
                .map_err(|e| TlsConfigError::FileRead(peer_cert_path.to_string(), e.to_string()))?;
            for cert in rustls_pemfile::certs(&mut peer_pem.as_slice()) {
                let cert = cert.map_err(|e| TlsConfigError::Parse(e.to_string()))?;
                peer_id_map.insert(cert.as_ref().to_vec(), peer_id.clone());
                root_store.add(cert).map_err(|e| TlsConfigError::Parse(e.to_string()))?;
            }
        }
        // Also trust our own cert.
        root_store.add(cert_der.clone()).map_err(|e| TlsConfigError::Parse(e.to_string()))?;
        peer_id_map.insert(cert_der.as_ref().to_vec(), vec![]); // self

        // C4 fix: server config requires client certificates (mTLS).
        let client_verifier =
            rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store.clone()))
                .build()
                .map_err(|e| TlsConfigError::Parse(e.to_string()))?;
        let server_config = rustls::ServerConfig::builder()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(vec![cert_der.clone()], key_der.clone_key())
            .map_err(|e| TlsConfigError::Parse(e.to_string()))?;
        let server_config = Arc::new(server_config);

        // C4 fix: client config presents our certificate (mTLS).
        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_client_auth_cert(vec![cert_der.clone()], key_der)
            .map_err(|e| TlsConfigError::Parse(e.to_string()))?;
        let client_config = Arc::new(client_config);

        let cert_der_vec = cert_der.as_ref().to_vec();
        Ok(Self { server_config, client_config, cert_der: cert_der_vec, peer_id_map })
    }

    /// Generate a self-signed certificate and return the DER bytes.
    ///
    /// Use this to generate certificates for all devnet nodes, then
    /// pass the DER bytes to [`self_signed`](Self::self_signed) as
    /// the `trusted_peers` argument.
    ///
    /// # Panics
    ///
    /// Panics if the generated PEM certificate fails to parse (should
    /// not happen — `rcgen` produces valid PEM).
    pub fn generate_self_signed_cert_der(peer_id: &[u8]) -> Vec<u8> {
        let (cert_pem, _) = generate_ca_cert_pem(peer_id);
        let cert_der = rustls_pemfile::certs(&mut cert_pem.as_bytes())
            .next()
            .expect("at least one cert in PEM")
            .expect("cert PEM must be valid");
        cert_der.as_ref().to_vec()
    }

    /// C4 fix: extract the authenticated peer ID from the verified
    /// client certificate.
    ///
    /// After the TLS handshake, the server has verified the client's
    /// certificate chain against the trust store. This method looks
    /// up the peer ID from the `peer_id_map` using the end-entity
    /// certificate's DER bytes.
    ///
    /// Returns `None` if no client certificate was presented or the
    /// certificate is not in the `peer_id_map`.
    pub fn extract_peer_id(
        &self,
        certs: Option<&[rustls::pki_types::CertificateDer<'static>]>,
    ) -> Option<Vec<u8>> {
        let certs = certs?;
        let end_entity = certs.first()?;
        self.peer_id_map.get(end_entity.as_ref()).cloned()
    }
}

/// Encode a peer ID as a hex string for certificate CNs.
#[cfg(feature = "tls")]
fn hex_id(id: &[u8]) -> String {
    id.iter().fold(String::with_capacity(id.len() * 2), |mut acc, b| {
        use std::fmt::Write;
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

/// Generate a self-signed end-entity certificate with the peer ID as
/// CN and "localhost" as a DNS SAN.
///
/// Uses PEM serialization for compatibility with rustls's PEM
/// parser (the same code path as `from_files`).
///
/// Returns `(cert_pem, key_pem)`.
///
/// # Panics
///
/// Panics if `rcgen` fails to generate the self-signed certificate
/// (should not happen with valid parameters).
#[cfg(feature = "tls")]
pub fn generate_ca_cert_pem(peer_id: &[u8]) -> (String, String) {
    use rcgen::generate_simple_self_signed;

    let cn = format!("oxide-peer-{}", hex_id(peer_id));
    let certified_key = generate_simple_self_signed(vec![cn, "localhost".to_string()])
        .expect("self-signed cert generation");
    let cert_pem = certified_key.cert.pem();
    let key_pem = certified_key.signing_key.serialize_pem();
    (cert_pem, key_pem)
}

/// TLS configuration loading/parsing errors.
#[cfg(feature = "tls")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsConfigError {
    /// The file could not be read.
    FileRead(String, String),
    /// The file could not be parsed.
    Parse(String),
}

#[cfg(feature = "tls")]
impl std::fmt::Display for TlsConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FileRead(path, reason) => write!(f, "cannot read TLS file {path}: {reason}"),
            Self::Parse(reason) => write!(f, "cannot parse TLS config: {reason}"),
        }
    }
}

#[cfg(feature = "tls")]
impl std::error::Error for TlsConfigError {}

#[cfg(test)]
#[cfg(feature = "tls")]
mod tests {
    use super::*;

    /// Self-signed config generates valid server and client configs.
    #[test]
    fn self_signed_config_works() {
        let peer_id = vec![0u8];
        let cert_der = TlsConfig::generate_self_signed_cert_der(&peer_id);
        let config = TlsConfig::self_signed(&peer_id, vec![(peer_id.clone(), cert_der)]);
        // The configs should be valid (Arc strong count > 0).
        assert!(Arc::strong_count(&config.server_config) > 0);
        assert!(Arc::strong_count(&config.client_config) > 0);
    }

    /// Multiple self-signed configs can trust each other (mTLS).
    #[test]
    fn multi_node_self_signed() {
        let id_a = vec![0u8];
        let id_b = vec![1u8];
        let cert_a = TlsConfig::generate_self_signed_cert_der(&id_a);
        let cert_b = TlsConfig::generate_self_signed_cert_der(&id_b);

        let config_a = TlsConfig::self_signed(&id_a, vec![(id_b.clone(), cert_b.clone())]);
        let config_b = TlsConfig::self_signed(&id_b, vec![(id_a.clone(), cert_a.clone())]);

        // Both configs should be valid.
        assert!(Arc::strong_count(&config_a.server_config) > 0);
        assert!(Arc::strong_count(&config_b.server_config) > 0);

        // C4: peer_id_map should contain the trusted peer's cert → ID.
        assert_eq!(
            config_a.extract_peer_id(Some(&[rustls::pki_types::CertificateDer::from(cert_b)])),
            Some(id_b)
        );
        assert_eq!(
            config_b.extract_peer_id(Some(&[rustls::pki_types::CertificateDer::from(cert_a)])),
            Some(id_a)
        );
    }

    /// C4: `extract_peer_id` returns None for an untrusted cert.
    #[test]
    fn extract_peer_id_rejects_untrusted_cert() {
        let peer_id = vec![0u8];
        let cert_der = TlsConfig::generate_self_signed_cert_der(&peer_id);
        let config = TlsConfig::self_signed(&peer_id, vec![(peer_id.clone(), cert_der.clone())]);

        // An untrusted cert should not resolve to any peer ID.
        let untrusted_cert = TlsConfig::generate_self_signed_cert_der(&[99u8]);
        assert_eq!(
            config
                .extract_peer_id(Some(&[rustls::pki_types::CertificateDer::from(untrusted_cert)])),
            None
        );
    }

    /// C4: `extract_peer_id` returns None when no cert is presented.
    #[test]
    fn extract_peer_id_returns_none_for_no_cert() {
        let peer_id = vec![0u8];
        let cert_der = TlsConfig::generate_self_signed_cert_der(&peer_id);
        let config = TlsConfig::self_signed(&peer_id, vec![(peer_id.clone(), cert_der)]);
        assert_eq!(config.extract_peer_id(None), None);
    }

    /// C4: full mTLS handshake — two nodes connect and exchange
    /// data over mutual TLS. The server verifies the client cert
    /// and extracts the peer ID from the verified certificate.
    #[test]
    fn mtls_handshake_exchange() {
        use std::io::{Read, Write};
        use std::net::{TcpListener, TcpStream};

        // Install the aws_lc_rs crypto provider as the process default.
        // rustls 0.23 requires this before using `builder()`.
        rustls::crypto::aws_lc_rs::default_provider().install_default().ok();

        let id_a = vec![0u8];
        let id_b = vec![1u8];
        // Generate certs and keys ONCE, then share between configs.
        // This ensures A trusts B's actual cert (not a separately
        // generated one) and vice versa.
        let (cert_pem_a, key_pem_a) = generate_ca_cert_pem(&id_a);
        let (cert_pem_b, key_pem_b) = generate_ca_cert_pem(&id_b);
        // Parse cert DERs for the trusted_peers map.
        let cert_der_a = rustls_pemfile::certs(&mut cert_pem_a.as_bytes())
            .next()
            .unwrap()
            .unwrap()
            .as_ref()
            .to_vec();
        let cert_der_b = rustls_pemfile::certs(&mut cert_pem_b.as_bytes())
            .next()
            .unwrap()
            .unwrap()
            .as_ref()
            .to_vec();
        let tls_a = TlsConfig::with_cert_pem(
            &id_a,
            &cert_pem_a,
            &key_pem_a,
            vec![(id_b.clone(), cert_der_b.clone())],
        );
        let tls_b = TlsConfig::with_cert_pem(
            &id_b,
            &cert_pem_b,
            &key_pem_b,
            vec![(id_a.clone(), cert_der_a.clone())],
        );

        let listener = TcpListener::bind("127.0.0.1:19350").unwrap();

        // A connects in a thread.
        let client_config = tls_a.client_config.clone();
        let send_id = id_a.clone();
        let join = std::thread::spawn(move || {
            let stream = TcpStream::connect("127.0.0.1:19350").unwrap();
            let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
            let client_conn = rustls::ClientConnection::new(client_config, server_name).unwrap();
            let mut tls_stream = rustls::StreamOwned::new(client_conn, stream);
            // Write peer ID frame (4-byte LE length + payload).
            let frame = u32::try_from(send_id.len()).unwrap().to_le_bytes();
            tls_stream.write_all(&frame).unwrap();
            tls_stream.write_all(&send_id).unwrap();
            // Read response.
            let mut buf = [0u8; 5];
            tls_stream.read_exact(&mut buf).unwrap();
            assert_eq!(&buf, b"hello");
        });

        // B accepts and verifies.
        let (stream, _) = listener.accept().unwrap();
        let server_conn = rustls::ServerConnection::new(tls_b.server_config.clone()).unwrap();
        let mut tls_stream = rustls::StreamOwned::new(server_conn, stream);
        // Read peer ID frame.
        let mut len_buf = [0u8; 4];
        tls_stream.read_exact(&mut len_buf).unwrap();
        let len = u32::from_le_bytes(len_buf) as usize;
        let mut id_buf = vec![0u8; len];
        tls_stream.read_exact(&mut id_buf).unwrap();
        assert_eq!(id_buf, id_a);

        // Verify peer cert extraction.
        let peer_certs = tls_stream.conn.peer_certificates();
        assert!(peer_certs.is_some(), "server should have client cert");
        let peer_id = tls_b.extract_peer_id(peer_certs);
        assert_eq!(peer_id, Some(id_a));

        // Send response.
        tls_stream.write_all(b"hello").unwrap();
        join.join().unwrap();
    }
}
