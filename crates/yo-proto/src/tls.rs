//! TLS 1.3 with mutual authentication.
//!
//! * Every device presents a self-signed Ed25519 client certificate. The
//!   server does not use a CA: a device *is* its key, identified by the
//!   SHA-256 hash of the certificate's SubjectPublicKeyInfo (SPKI).
//! * Clients authenticate the server either by **pinning** the SHA-256 of the
//!   server certificate's SPKI (self-signed servers) or with the normal web
//!   PKI (servers with e.g. a Let's Encrypt certificate).
//!
//! TLS protects the client↔server hop only. Message privacy comes from the
//! end-to-end layer in `yo-crypto`.

use std::path::Path;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms, verify_tls13_signature};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{CertificateError, DigitallySignedStruct, DistinguishedName, SignatureScheme};
use sha2::{Digest, Sha256};

use crate::{ALPN, b32, from_b32};

#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("tls: {0}")]
    Rustls(#[from] rustls::Error),
    #[error("certificate generation: {0}")]
    Rcgen(#[from] rcgen::Error),
    #[error("pem: {0}")]
    Pem(#[from] rustls::pki_types::pem::Error),
    #[error("could not parse certificate")]
    BadCert,
    #[error("invalid pin (expected sha256:<base32>)")]
    BadPin,
}

pub type Chain = Vec<CertificateDer<'static>>;

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn algs() -> WebPkiSupportedAlgorithms {
    rustls::crypto::ring::default_provider().signature_verification_algorithms
}

/// SHA-256 of a certificate's SubjectPublicKeyInfo.
pub fn spki_hash(cert: &CertificateDer<'_>) -> Result<[u8; 32], TlsError> {
    let (_, parsed) = x509_parser::parse_x509_certificate(cert.as_ref()).map_err(|_| TlsError::BadCert)?;
    Ok(Sha256::digest(parsed.tbs_certificate.subject_pki.raw).into())
}

pub fn format_pin(hash: &[u8; 32]) -> String {
    format!("sha256:{}", b32(hash))
}

pub fn parse_pin(s: &str) -> Result<[u8; 32], TlsError> {
    let rest = s.trim().strip_prefix("sha256:").ok_or(TlsError::BadPin)?;
    from_b32(rest).and_then(|v| v.try_into().ok()).ok_or(TlsError::BadPin)
}

/// Generate a self-signed Ed25519 certificate. Returns `(cert_pem, key_pem)`.
pub fn generate_cert(names: Vec<String>) -> Result<(String, String), TlsError> {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)?;
    let mut params = rcgen::CertificateParams::new(names)?;
    params.distinguished_name.push(rcgen::DnType::CommonName, "yo!");
    let cert = params.self_signed(&key)?;
    Ok((cert.pem(), key.serialize_pem()))
}

pub fn load_chain(pem: &[u8]) -> Result<Chain, TlsError> {
    let chain = CertificateDer::pem_slice_iter(pem).collect::<Result<Vec<_>, _>>()?;
    if chain.is_empty() {
        return Err(TlsError::BadCert);
    }
    Ok(chain)
}

pub fn load_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>, TlsError> {
    Ok(PrivateKeyDer::from_pem_slice(pem)?)
}

pub fn load_chain_file(path: &Path) -> std::io::Result<Chain> {
    load_chain(&std::fs::read(path)?).map_err(std::io::Error::other)
}

pub fn load_key_file(path: &Path) -> std::io::Result<PrivateKeyDer<'static>> {
    load_key(&std::fs::read(path)?).map_err(std::io::Error::other)
}

/// How the client decides the server is genuine.
#[derive(Clone, Debug)]
pub enum ServerTrust {
    /// Accept only a certificate whose SPKI hashes to this value.
    Pinned([u8; 32]),
    /// Normal CA validation against the Mozilla root store.
    WebPki,
}

pub fn client_config(
    chain: Chain,
    key: PrivateKeyDer<'static>,
    trust: ServerTrust,
) -> Result<rustls::ClientConfig, TlsError> {
    let builder = rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?;
    let mut cfg = match trust {
        ServerTrust::Pinned(pin) => builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedServer { pin, algs: algs() }))
            .with_client_auth_cert(chain, key)?,
        ServerTrust::WebPki => {
            let roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
            builder.with_root_certificates(roots).with_client_auth_cert(chain, key)?
        }
    };
    cfg.alpn_protocols = vec![ALPN.to_vec()];
    Ok(cfg)
}

pub fn server_config(chain: Chain, key: PrivateKeyDer<'static>) -> Result<rustls::ServerConfig, TlsError> {
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(Arc::new(AnyClientCert { algs: algs() }))
        .with_single_cert(chain, key)?;
    cfg.alpn_protocols = vec![ALPN.to_vec()];
    Ok(cfg)
}

/// Build a `ServerName` from a host that may be a DNS name or an IP address.
pub fn server_name(host: &str) -> Result<ServerName<'static>, TlsError> {
    ServerName::try_from(host.to_string()).map_err(|_| TlsError::BadCert)
}

#[derive(Debug)]
struct PinnedServer {
    pin: [u8; 32],
    algs: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for PinnedServer {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let hash = spki_hash(end_entity).map_err(|_| rustls::Error::InvalidCertificate(CertificateError::BadEncoding))?;
        if hash == self.pin {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("TLS 1.2 is not supported".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

/// Accepts any well-formed client certificate; possession of the private key
/// is proven by the TLS 1.3 handshake signature. Authorization happens at
/// the application layer based on the SPKI hash.
#[derive(Debug)]
struct AnyClientCert {
    algs: WebPkiSupportedAlgorithms,
}

impl ClientCertVerifier for AnyClientCert {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        spki_hash(end_entity).map_err(|_| rustls::Error::InvalidCertificate(CertificateError::BadEncoding))?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("TLS 1.2 is not supported".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pin_roundtrip() {
        let (cert, _) = generate_cert(vec!["localhost".into()]).unwrap();
        let chain = load_chain(cert.as_bytes()).unwrap();
        let h = spki_hash(&chain[0]).unwrap();
        assert_eq!(parse_pin(&format_pin(&h)).unwrap(), h);
        assert!(parse_pin("md5:abc").is_err());
    }
}
