use crate::{
    HandshakeError, HandshakeResult, Identity, MidHandshakeTlsStream, TLSConfig, TcpStream,
};

use native_tls::Certificate;
use std::io;

/// Reexport native-tls's `TlsConnector`
pub use native_tls::TlsConnector as NativeTlsConnector;

/// A `TcpStream` wrapped by native-tls
pub type NativeTlsStream = native_tls::TlsStream<TcpStream>;

/// A `MidHandshakeTlsStream` from native-tls
pub type NativeTlsMidHandshakeTlsStream = native_tls::MidHandshakeTlsStream<TcpStream>;

/// A `HandshakeError` from native-tls
pub type NativeTlsHandshakeError = native_tls::HandshakeError<TcpStream>;

fn native_tls_connector(config: TLSConfig<'_, '_, '_>) -> io::Result<NativeTlsConnector> {
    let mut builder = NativeTlsConnector::builder();
    if let Some(identity) = config.identity {
        let native_identity = match identity {
            Identity::PKCS8 { pem, key } => native_tls::Identity::from_pkcs8(pem, key),
            Identity::PKCS12 { der, password } => native_tls::Identity::from_pkcs12(der, password),
        };
        builder.identity(native_identity.map_err(io::Error::other)?);
    }
    if let Some(cert_chain) = config.cert_chain {
        let mut cert_chain = std::io::BufReader::new(cert_chain.as_bytes());
        for cert in rustls_pemfile::certs(&mut cert_chain).collect::<Result<Vec<_>, _>>()? {
            builder
                .add_root_certificate(Certificate::from_der(&cert[..]).map_err(io::Error::other)?);
        }
    }
    builder.build().map_err(io::Error::other)
}

#[allow(dead_code)]
pub(crate) fn into_native_tls_impl(
    s: TcpStream,
    domain: &str,
    config: TLSConfig<'_, '_, '_>,
) -> HandshakeResult {
    s.into_native_tls(&native_tls_connector(config)?, domain)
}

impl From<NativeTlsStream> for TcpStream {
    fn from(s: NativeTlsStream) -> Self {
        TcpStream::NativeTls(Box::new(s))
    }
}

impl From<NativeTlsMidHandshakeTlsStream> for MidHandshakeTlsStream {
    fn from(mid: NativeTlsMidHandshakeTlsStream) -> Self {
        MidHandshakeTlsStream::NativeTls(mid)
    }
}

impl From<NativeTlsHandshakeError> for HandshakeError {
    fn from(error: NativeTlsHandshakeError) -> Self {
        match error {
            native_tls::HandshakeError::WouldBlock(mid) => HandshakeError::WouldBlock(mid.into()),
            native_tls::HandshakeError::Failure(failure) => {
                HandshakeError::Failure(io::Error::other(failure))
            }
        }
    }
}
