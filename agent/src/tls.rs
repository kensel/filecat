//! TLS: a self-signed certificate generated on first start (trust on first use: the client pins the
//! SHA-256 of the DER leaf), served by rustls with the `ring` provider (TLS 1.2 and 1.3, no OpenSSL,
//! no C beyond what ring itself builds).

use rcgen::{CertificateParams, DnType, KeyPair};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::Arc;

pub struct Tls {
    pub config: Arc<rustls::ServerConfig>,
    /// lowercase hex SHA-256 of the DER leaf certificate
    pub fingerprint: String,
    pub generated: bool,
}

fn write_private(path: &Path, data: &[u8]) -> Result<(), String> {
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    f.write_all(data).map_err(|e| format!("{}: {e}", path.display()))
}

fn generate(cert_path: &Path, key_path: &Path) -> Result<(), String> {
    let mut params = CertificateParams::new(vec!["filecat-agent".to_string(), "localhost".to_string()]).map_err(|e| e.to_string())?;
    params.distinguished_name.push(DnType::CommonName, "filecat-agent");
    let key = KeyPair::generate().map_err(|e| e.to_string())?;
    let cert = params.self_signed(&key).map_err(|e| e.to_string())?;
    // the key first, with 0600 from the start; never overwrite an existing pair
    write_private(key_path, key.serialize_pem().as_bytes())?;
    std::fs::write(cert_path, cert.pem()).map_err(|e| format!("{}: {e}", cert_path.display()))
}

/// Load the pair, generating it when both files are missing. One of the two alone is an error:
/// replacing half of a pair would silently change the fingerprint the clients pinned.
pub fn load_or_generate(cert_path: &Path, key_path: &Path) -> Result<Tls, String> {
    let generated = match (cert_path.exists(), key_path.exists()) {
        (false, false) => {
            generate(cert_path, key_path)?;
            true
        }
        (true, true) => false,
        _ => return Err(format!("only one of {} and {} exists; remove it or restore the other", cert_path.display(), key_path.display())),
    };
    let cert_pem = std::fs::read(cert_path).map_err(|e| format!("{}: {e}", cert_path.display()))?;
    let key_pem = std::fs::read(key_path).map_err(|e| format!("{}: {e}", key_path.display()))?;
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&cert_pem).collect::<Result<_, _>>().map_err(|e| format!("{}: {e}", cert_path.display()))?;
    let leaf = certs.first().ok_or_else(|| format!("{}: no certificate", cert_path.display()))?;
    let fingerprint = crate::proto::hex(&Sha256::digest(leaf.as_ref()));
    let key = PrivateKeyDer::from_pem_slice(&key_pem).map_err(|e| format!("{}: {e}", key_path.display()))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| e.to_string())?;
    Ok(Tls { config: Arc::new(config), fingerprint, generated })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_once_and_keeps_the_fingerprint() {
        let d = std::env::temp_dir().join(format!("fc-tls-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let (c, k) = (d.join("a.crt"), d.join("a.key"));
        let first = load_or_generate(&c, &k).unwrap();
        assert!(first.generated && first.fingerprint.len() == 64);
        let again = load_or_generate(&c, &k).unwrap();
        assert!(!again.generated);
        assert_eq!(first.fingerprint, again.fingerprint);
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&k).unwrap().permissions().mode() & 0o777, 0o600);
        std::fs::remove_file(&k).unwrap();
        assert!(load_or_generate(&c, &k).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }
}
