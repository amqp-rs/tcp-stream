use crate::{
    HandshakeError, HandshakeResult, Identity, MidHandshakeTlsStream, TLSConfig, TcpStream,
};

#[cfg(feature = "rustls-futures")]
use crate::AsyncTcpStream;

use rustls_connector::rustls_pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, pem::PemObject,
};
use std::io;

/// Reexport rustls-connector's `TlsConnector`
pub use rustls_connector::{RustlsConnector, RustlsConnectorConfig};

/// A `TcpStream` wrapped by rustls
pub type RustlsStream = rustls_connector::TlsStream<TcpStream>;

/// A `MidHandshakeTlsStream` from rustls-connector
pub type RustlsMidHandshakeTlsStream = rustls_connector::MidHandshakeTlsStream<TcpStream>;

/// A `HandshakeError` from rustls-connector
pub type RustlsHandshakeError = rustls_connector::HandshakeError<TcpStream>;

fn update_rustls_config(
    c: &mut RustlsConnectorConfig,
    config: &TLSConfig<'_, '_, '_>,
) -> io::Result<()> {
    if let Some(cert_chain) = config.cert_chain {
        let mut cert_chain = std::io::BufReader::new(cert_chain.as_bytes());
        let certs = rustls_pemfile::certs(&mut cert_chain)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        c.add_parsable_certificates(certs);
    }
    Ok(())
}

fn rustls_identity(
    identity: Identity<'_, '_>,
) -> io::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let (certs, key) = match identity {
        Identity::PKCS12 { der, password } => {
            let pfx =
                p12_keystore::KeyStore::from_pkcs12(der, password).map_err(io::Error::other)?;
            let Some((_, keychain)) = pfx.private_key_chain() else {
                return Err(io::Error::other("No private key in pkcs12 DER"));
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
            let mut cert_reader = std::io::BufReader::new(pem);
            let certs = rustls_pemfile::certs(&mut cert_reader)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
            (
                certs,
                PrivateKeyDer::from_pem_slice(key)
                    .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?,
            )
        }
    };
    Ok((certs, key))
}

fn rustls_connector(
    mut c: RustlsConnectorConfig,
    config: TLSConfig<'_, '_, '_>,
) -> io::Result<RustlsConnector> {
    update_rustls_config(&mut c, &config)?;

    let connector = if let Some(identity) = config.identity {
        let (certs, key) = rustls_identity(identity)?;
        c.connector_with_single_cert(certs, key)
            .map_err(io::Error::other)?
    } else {
        c.connector_with_no_client_auth()
    };
    Ok(connector)
}

#[allow(dead_code)]
pub(crate) fn into_rustls_impl(
    s: TcpStream,
    c: RustlsConnectorConfig,
    domain: &str,
    config: TLSConfig<'_, '_, '_>,
) -> HandshakeResult {
    s.into_rustls(&rustls_connector(c, config)?, domain)
}

#[cfg(feature = "rustls-futures")]
#[allow(dead_code)]
pub(crate) async fn into_rustls_impl_async(
    s: AsyncTcpStream,
    c: RustlsConnectorConfig,
    domain: &str,
    config: TLSConfig<'_, '_, '_>,
) -> io::Result<AsyncTcpStream> {
    s.into_rustls(&rustls_connector(c, config)?, domain).await
}

impl From<RustlsStream> for TcpStream {
    fn from(s: RustlsStream) -> Self {
        TcpStream::Rustls(Box::new(s))
    }
}

impl From<RustlsMidHandshakeTlsStream> for MidHandshakeTlsStream {
    fn from(mid: RustlsMidHandshakeTlsStream) -> Self {
        MidHandshakeTlsStream::Rustls(mid)
    }
}

impl From<RustlsHandshakeError> for HandshakeError {
    fn from(error: RustlsHandshakeError) -> Self {
        match error {
            rustls_connector::HandshakeError::WouldBlock(mid) => {
                HandshakeError::WouldBlock((*mid).into())
            }
            rustls_connector::HandshakeError::Failure(failure) => HandshakeError::Failure(failure),
        }
    }
}
