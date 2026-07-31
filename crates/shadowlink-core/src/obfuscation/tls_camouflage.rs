//! # TLS Camouflage Transport
//!
//! Wraps the ShadowLink protocol inside a real TLS 1.3 connection.
//! To any DPI system, this looks like standard HTTPS traffic.
//!
//! ## How it works:
//! 1. Client connects to server on port 443 (standard HTTPS)
//! 2. A real TLS 1.3 handshake occurs (using rustls)
//! 3. Inside the TLS tunnel, the ShadowLink handshake + data flows
//! 4. DPI sees: normal TLS 1.3 to an HTTPS server — nothing suspicious
//!
//! ## Compared to XTLS-Reality:
//! - Reality steals certificates from real sites — clever but known/detectable
//! - ShadowLink uses its own TLS cert on the server, but the server also
//!   serves a real decoy website to probers, making it look like a real site

use anyhow::{Context, Result};
use rustls::pki_types::ServerName;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector, TlsStream};

/// Configuration for the TLS camouflage layer
#[derive(Clone)]
pub struct TlsCamouflageConfig {
    /// The SNI hostname to present in the TLS ClientHello.
    /// Should match the server's certificate or a plausible domain.
    pub sni_hostname: String,

    /// Whether to verify the server's TLS certificate.
    /// Set to false for self-signed certs (typical for personal use).
    pub verify_server_cert: bool,
}

impl Default for TlsCamouflageConfig {
    fn default() -> Self {
        Self {
            sni_hostname: "www.example.com".to_string(),
            verify_server_cert: false,
        }
    }
}

/// Create a TLS client connector for camouflaging client connections.
///
/// When `verify_cert` is false, all server certificates are accepted
/// (since we authenticate via the ShadowLink handshake instead).
pub fn create_client_tls_config(config: &TlsCamouflageConfig) -> Result<TlsConnector> {
    let tls_config = if config.verify_server_cert {
        // Use system root certificates
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    } else {
        // Accept any certificate — we authenticate via ShadowLink handshake
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth()
    };

    Ok(TlsConnector::from(Arc::new(tls_config)))
}

/// Connect to a server with TLS camouflage.
///
/// Returns a TLS-wrapped TCP stream that looks like normal HTTPS to DPI.
pub async fn tls_connect(
    tcp_stream: TcpStream,
    connector: &TlsConnector,
    sni: &str,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let server_name = ServerName::try_from(sni.to_string())
        .map_err(|_| anyhow::anyhow!("Invalid SNI hostname: {}", sni))?;

    connector
        .connect(server_name, tcp_stream)
        .await
        .context("TLS handshake failed")
}

/// Create a TLS server acceptor from certificate and private key PEM data.
///
/// The server presents this certificate to all connections (including DPI probers).
pub fn create_server_tls_config(
    cert_pem: &[u8],
    key_pem: &[u8],
) -> Result<TlsAcceptor> {
    let certs = rustls_pemfile::certs(&mut std::io::BufReader::new(cert_pem))
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("Failed to parse TLS certificate")?;

    let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(key_pem))
        .context("Failed to read TLS private key")?
        .ok_or_else(|| anyhow::anyhow!("No private key found in PEM data"))?;

    let tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("Failed to build TLS server config")?;

    Ok(TlsAcceptor::from(Arc::new(tls_config)))
}

/// Accept a TLS connection on the server side.
pub async fn tls_accept(
    tcp_stream: TcpStream,
    acceptor: &TlsAcceptor,
) -> Result<tokio_rustls::server::TlsStream<TcpStream>> {
    acceptor
        .accept(tcp_stream)
        .await
        .context("TLS accept failed")
}

/// A certificate verifier that accepts everything.
/// Security comes from the ShadowLink handshake, not TLS certificate validation.
/// This prevents DPI from blocking us based on certificate transparency logs.
#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}
