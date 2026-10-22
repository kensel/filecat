use rcgen::{CertificateParams, KeyPair};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Cursor;
use std::path::Path;
use std::sync::Arc;

pub struct AgentTlsConfig {
    pub server_config: Arc<rustls::ServerConfig>,
    pub cert_sha256: String,
}

/// Loads existing cert/key from disk or generates a new self-signed Ed25519 certificate
/// for TOFU (Trust-On-First-Use) SHA-256 fingerprint pinning in filecat.toml.
pub fn load_or_generate_tls(cert_path: &Path, key_path: &Path) -> Result<AgentTlsConfig, String> {
    if !cert_path.exists() || !key_path.exists() {
        let mut params = CertificateParams::new(vec![
            "filecat-agent.local".to_string(),
            "localhost".to_string(),
        ])
        .map_err(|e| e.to_string())?;
        let key_pair = KeyPair::generate().map_err(|e| e.to_string())?;
        let cert = params.self_signed(&key_pair).map_err(|e| e.to_string())?;

        fs::write(cert_path, cert.pem()).map_err(|e| e.to_string())?;
        fs::write(key_path, key_pair.serialize_pem()).map_err(|e| e.to_string())?;
    }

    let cert_pem = fs::read(cert_path).map_err(|e| e.to_string())?;
    let key_pem = fs::read(key_path).map_err(|e| e.to_string())?;

    let mut cert_reader = Cursor::new(&cert_pem);
    let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;

    if certs.is_empty() {
        return Err("No certificates found in PEM file".to_string());
    }

    let mut hasher = Sha256::new();
    hasher.update(certs[0].as_ref());
    let cert_sha256 = format!("{:x}", hasher.finalize());

    let mut key_reader = Cursor::new(&key_pem);
    let key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "No private key found in PEM file".to_string())?;

    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| e.to_string())?;

    Ok(AgentTlsConfig {
        server_config: Arc::new(server_config),
        cert_sha256,
    })
}
