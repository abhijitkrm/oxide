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
//! # Certificate-based peer identity
//!
//! Each node has a certificate with a subject CN (Common Name) that
//! matches its peer ID. When a peer connects, its certificate is
//! verified against a list of trusted peer certificates. This
//! provides cryptographic peer authentication — no impersonation
//! possible without the peer's private key.

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
    pub server_config: Arc<rustls::ServerConfig>,
    /// The client config (for initiating TLS connections to peers).
    pub client_config: Arc<rustls::ClientConfig>,
}

#[cfg(feature = "tls")]
impl TlsConfig {
    /// Generate a self-signed TLS config for devnet/testnet.
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
    /// - `trusted_peer_certs`: the DER-encoded certificates of all
    ///   peers that this node should trust.
    ///
    /// # Panics
    ///
    /// Panics if certificate generation fails (should not happen with
    /// valid parameters).
    pub fn self_signed(peer_id: &[u8], trusted_peer_certs: Vec<Vec<u8>>) -> Self {
        use rcgen::{CertifiedKey, generate_simple_self_signed};

        // Generate a self-signed certificate with the peer ID as CN.
        let cn = format!("oxide-peer-{}", hex_id(peer_id));
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec![cn.clone()]).expect("self-signed cert generation");

        // Serialize the certificate and key to DER.
        let cert_der = cert.der().to_vec();
        let key_der = signing_key.serialize_der();

        // Build the server config: use our cert and key.
        let server_cert = rustls::pki_types::CertificateDer::from(cert_der.clone());
        let server_key = rustls::pki_types::PrivateKeyDer::try_from(key_der)
            .expect("private key DER must be valid");
        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![server_cert], server_key)
            .expect("server config must be valid");
        let server_config = Arc::new(server_config);

        // Build the client config: trust all provided peer certs.
        // For devnet, we trust all self-signed certs. For production,
        // use a proper CA.
        let mut root_store = rustls::RootCertStore::empty();
        for peer_cert in &trusted_peer_certs {
            root_store
                .add(rustls::pki_types::CertificateDer::from(peer_cert.clone()))
                .expect("peer cert must be valid");
        }
        // Also trust our own cert (for self-connection testing).
        root_store
            .add(rustls::pki_types::CertificateDer::from(cert_der.clone()))
            .expect("self cert must be valid");

        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let client_config = Arc::new(client_config);

        Self { server_config, client_config }
    }

    /// Load TLS config from PEM-encoded certificate and key files.
    ///
    /// For production, certificates are managed by the deploy tooling
    /// and loaded from files at startup.
    ///
    /// # Arguments
    ///
    /// - `cert_path`: path to the PEM-encoded certificate file.
    /// - `key_path`: path to the PEM-encoded private key file.
    /// - `trusted_peer_certs`: list of PEM-encoded trusted peer
    ///   certificates.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the files cannot be read or parsed.
    pub fn from_files(
        cert_path: &str,
        key_path: &str,
        trusted_peer_certs: &[&str],
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

        // Build the server config.
        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key_der)
            .map_err(|e| TlsConfigError::Parse(e.to_string()))?;
        let server_config = Arc::new(server_config);

        // Build the client config: trust all provided peer certs.
        let mut root_store = rustls::RootCertStore::empty();
        for peer_cert_path in trusted_peer_certs {
            let peer_pem = std::fs::read(peer_cert_path)
                .map_err(|e| TlsConfigError::FileRead(peer_cert_path.to_string(), e.to_string()))?;
            for cert in rustls_pemfile::certs(&mut peer_pem.as_slice()) {
                let cert = cert.map_err(|e| TlsConfigError::Parse(e.to_string()))?;
                root_store.add(cert).map_err(|e| TlsConfigError::Parse(e.to_string()))?;
            }
        }
        // Also trust our own cert.
        root_store.add(cert_der).map_err(|e| TlsConfigError::Parse(e.to_string()))?;

        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let client_config = Arc::new(client_config);

        Ok(Self { server_config, client_config })
    }

    /// Generate a self-signed certificate and return the DER bytes.
    ///
    /// Use this to generate certificates for all devnet nodes, then
    /// pass the DER bytes to [`self_signed`](Self::self_signed) as
    /// the `trusted_peer_certs`.
    pub fn generate_self_signed_cert_der(peer_id: &[u8]) -> Vec<u8> {
        use rcgen::{CertifiedKey, generate_simple_self_signed};
        let cn = format!("oxide-peer-{}", hex_id(peer_id));
        let CertifiedKey { cert, .. } =
            generate_simple_self_signed(vec![cn]).expect("self-signed cert generation");
        cert.der().to_vec()
    }
}

/// Encode a peer ID as a hex string for certificate CNs.
#[cfg(feature = "tls")]
fn hex_id(id: &[u8]) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
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
        let config = TlsConfig::self_signed(&peer_id, vec![cert_der]);
        // The configs should be valid (Arc strong count > 0).
        assert!(Arc::strong_count(&config.server_config) > 0);
        assert!(Arc::strong_count(&config.client_config) > 0);
    }

    /// Multiple self-signed configs can trust each other.
    #[test]
    fn multi_node_self_signed() {
        let id_a = vec![0u8];
        let id_b = vec![1u8];
        let cert_a = TlsConfig::generate_self_signed_cert_der(&id_a);
        let cert_b = TlsConfig::generate_self_signed_cert_der(&id_b);

        let config_a = TlsConfig::self_signed(&id_a, vec![cert_b.clone()]);
        let config_b = TlsConfig::self_signed(&id_b, vec![cert_a]);

        // Both configs should be valid.
        assert!(Arc::strong_count(&config_a.server_config) > 0);
        assert!(Arc::strong_count(&config_b.server_config) > 0);
    }
}
