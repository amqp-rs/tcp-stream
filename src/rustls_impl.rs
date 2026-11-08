use crate::{
    HandshakeError, HandshakeResult, Identity, MidHandshakeTlsStream, StdTcpStream, TLSConfig,
    TcpStream,
};

#[cfg(feature = "rustls-futures")]
use {
    crate::AsyncTcpStream,
    futures_io::{AsyncRead, AsyncWrite},
};

use rustls_connector::rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::io;

/// Reexport rustls-connector's `TlsConnector`
pub use rustls_connector::{RustlsConnector, RustlsConnectorConfig};

/// A `TcpStream` wrapped by rustls
pub type RustlsStream = rustls_connector::TlsStream<StdTcpStream>;

/// A `MidHandshakeTlsStream` from rustls-connector
pub type RustlsMidHandshakeTlsStream = rustls_connector::MidHandshakeTlsStream<StdTcpStream>;

/// A `HandshakeError` from rustls-connector
pub type RustlsHandshakeError = rustls_connector::HandshakeError<StdTcpStream>;

#[cfg(feature = "rustls-futures")]
/// An async `TcpStream` wrapped by rustls
pub type RustlsAsyncStream<S> = rustls_connector::AsyncTlsStream<S>;

fn update_rustls_config(
    c: &mut RustlsConnectorConfig,
    config: &TLSConfig<'_, '_, '_>,
) -> io::Result<()> {
    if let Some(cert_chain) = config.cert_chain {
        let certs = crate::pem::custom_roots(cert_chain)?;
        // Custom roots are explicit configuration, so reject invalid entries
        // before the connector's best-effort root loading can discard them.
        for cert in &certs {
            rustls_connector::webpki::anchor_from_trusted_cert(cert)
                .map_err(crate::invalid_data)?;
        }
        c.add_parsable_certificates(certs);
    }
    Ok(())
}

fn rustls_identity(
    identity: Identity<'_, '_>,
) -> io::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let (certs, key) = match identity {
        Identity::PKCS12 { der, password } => {
            // The 0.2 importer does not stop at certificate issuer cycles. Keep it
            // until the newer parser's prerelease dependencies settle.
            let pfx =
                p12_keystore::KeyStore::from_pkcs12(der, password).map_err(crate::invalid_data)?;
            let Some((_, keychain)) = pfx.private_key_chain() else {
                return Err(crate::invalid_data("No private key in pkcs12 DER"));
            };
            let certs = keychain
                .chain()
                .iter()
                .map(|cert| CertificateDer::from(cert.as_der().to_vec()))
                .collect();
            (
                certs,
                PrivateKeyDer::from(PrivatePkcs8KeyDer::from(keychain.key().to_vec())),
            )
        }
        Identity::PKCS8 { pem, key } => {
            let certs = crate::pem::identity_certificates(pem)?;
            // Reject what is not a certificate here, as the other backends do,
            // rather than sending it to the server.
            if !certs.iter().all(|cert| crate::pem::is_certificate(cert)) {
                return Err(crate::pem::invalid_identity_chain());
            }
            (
                certs,
                crate::pem::pem_any_private_key(key).ok_or_else(|| {
                    crate::invalid_data("PKCS#8 identity requires a valid PEM private key")
                })?,
            )
        }
    };
    Ok((certs, key))
}

fn select_connector_config() -> io::Result<RustlsConnectorConfig> {
    cfg_if::cfg_if! {
        if #[cfg(feature = "rustls-platform-verifier")] {
            Ok(RustlsConnectorConfig::new_with_platform_verifier())
        } else if #[cfg(feature = "rustls-native-certs")] {
            RustlsConnectorConfig::new_with_native_certs()
        } else if #[cfg(feature = "rustls-webpki-roots-certs")] {
            Ok(RustlsConnectorConfig::new_with_webpki_root_certs())
        } else {
            Ok(RustlsConnectorConfig::default())
        }
    }
}

pub(crate) fn into_rustls_impl(
    s: TcpStream,
    domain: &str,
    config: TLSConfig<'_, '_, '_>,
) -> HandshakeResult {
    s.into_rustls(&rustls_connector(config)?, domain)
}

pub(crate) fn rustls_connector(mut config: TLSConfig<'_, '_, '_>) -> io::Result<RustlsConnector> {
    // Reject an invalid identity before loading the certificate store, which
    // can fail on its own.
    let identity = config.identity.take().map(rustls_identity).transpose()?;
    let mut c = select_connector_config()?;
    update_rustls_config(&mut c, &config)?;

    let connector = if let Some((certs, key)) = identity {
        c.connector_with_single_cert(certs, key)?
    } else {
        c.connector_with_no_client_auth()?
    };
    Ok(connector)
}

#[cfg(feature = "rustls-futures")]
pub(crate) async fn into_rustls_impl_async<S: AsyncRead + AsyncWrite + Send + Unpin + 'static>(
    s: AsyncTcpStream<S>,
    domain: &str,
    config: TLSConfig<'_, '_, '_>,
) -> io::Result<AsyncTcpStream<S>> {
    s.into_rustls(&rustls_connector(config)?, domain).await
}

impl From<RustlsStream> for TcpStream {
    fn from(s: RustlsStream) -> Self {
        Self::Rustls(s)
    }
}

impl From<RustlsMidHandshakeTlsStream> for MidHandshakeTlsStream {
    fn from(mid: RustlsMidHandshakeTlsStream) -> Self {
        Self::Rustls(mid)
    }
}

impl From<RustlsHandshakeError> for HandshakeError {
    fn from(error: RustlsHandshakeError) -> Self {
        match error {
            rustls_connector::HandshakeError::WouldBlock(mid) => Self::WouldBlock(mid.into()),
            rustls_connector::HandshakeError::Failure(failure) => Self::Failure(failure),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_identity_chains_with_other_objects_as_certificates() {
        let not_a_certificate =
            crate::tests::ENCRYPTED_KEY.replace("ENCRYPTED PRIVATE KEY", "CERTIFICATE");
        let pem = [crate::tests::CERT_CHAIN, not_a_certificate.as_bytes()].concat();
        let error = rustls_identity(Identity::PKCS8 {
            pem: &pem,
            key: crate::tests::PRIVATE_KEY,
        })
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn rejects_malformed_pkcs12_as_invalid_data() {
        let error = rustls_identity(Identity::PKCS12 {
            der: b"not a PKCS12 bundle",
            password: "",
        })
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn validates_custom_roots() {
        crate::tests::check_custom_roots(|config| {
            update_rustls_config(&mut RustlsConnectorConfig::default(), &config)
        });
        update_rustls_config(
            &mut RustlsConnectorConfig::default(),
            &TLSConfig {
                identity: None,
                cert_chain: Some(crate::tests::ROOT_CERT),
            },
        )
        .unwrap();
    }

    #[test]
    fn accepts_pkcs8_identity_with_intermediates() {
        let (certs, _) = rustls_identity(Identity::PKCS8 {
            pem: crate::tests::CERT_CHAIN,
            key: crate::tests::PRIVATE_KEY,
        })
        .unwrap();
        assert_eq!(certs.len(), 3);
    }

    #[test]
    fn accepts_pkcs12_identity_with_intermediates() {
        let (certs, _) = rustls_identity(Identity::PKCS12 {
            der: crate::tests::PKCS12_IDENTITY,
            password: crate::tests::PKCS12_PASSWORD,
        })
        .unwrap();
        assert_eq!(certs.len(), 3);
    }
}
