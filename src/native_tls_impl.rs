use crate::{
    HandshakeError, HandshakeResult, Identity, MidHandshakeTlsStream, StdTcpStream, TLSConfig,
    TcpStream,
};

#[cfg(feature = "native-tls-futures")]
use {
    crate::AsyncTcpStream,
    futures_io::{AsyncRead, AsyncWrite},
};

use native_tls::Certificate;
use std::io;

/// Reexport native-tls's `TlsConnector`
pub use native_tls::TlsConnector as NativeTlsConnector;

/// Reexport native-tls's `TlsConnectorBuilder`
pub use native_tls::TlsConnectorBuilder as NativeTlsConnectorBuilder;

/// A `TcpStream` wrapped by native-tls
pub type NativeTlsStream = native_tls::TlsStream<StdTcpStream>;

/// A `MidHandshakeTlsStream` from native-tls
pub type NativeTlsMidHandshakeTlsStream = native_tls::MidHandshakeTlsStream<StdTcpStream>;

/// A `HandshakeError` from native-tls
pub type NativeTlsHandshakeError = native_tls::HandshakeError<StdTcpStream>;

#[cfg(feature = "native-tls-futures")]
/// An async `TcpStream` wrapped by native-tls
pub type NativeTlsAsyncStream<S> = async_native_tls::TlsStream<S>;

fn native_tls_connector_builder(
    config: TLSConfig<'_, '_, '_>,
) -> io::Result<NativeTlsConnectorBuilder> {
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
        for cert in
            CertificateDer::pem_reader_iter(&mut cert_chain).collect::<Result<Vec<_>, _>>()?
        {
            builder
                .add_root_certificate(Certificate::from_der(&cert[..]).map_err(io::Error::other)?);
        }
    }
    Ok(builder)
}

fn native_tls_connector(config: TLSConfig<'_, '_, '_>) -> io::Result<NativeTlsConnector> {
    native_tls_connector_builder(config)?
        .build()
        .map_err(io::Error::other)
}

#[allow(dead_code)]
pub(crate) fn into_native_tls_impl(
    s: TcpStream,
    domain: &str,
    config: TLSConfig<'_, '_, '_>,
) -> HandshakeResult {
    s.into_native_tls(&native_tls_connector(config)?, domain)
}

#[cfg(feature = "native-tls-futures")]
#[allow(dead_code)]
pub(crate) async fn into_native_tls_impl_async<
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
>(
    s: AsyncTcpStream<S>,
    domain: &str,
    config: TLSConfig<'_, '_, '_>,
) -> io::Result<AsyncTcpStream<S>> {
    s.into_native_tls(native_tls_connector_builder(config)?, domain)
        .await
}

impl From<NativeTlsStream> for TcpStream {
    fn from(s: NativeTlsStream) -> Self {
        Self::NativeTls(s)
    }
}

impl From<NativeTlsMidHandshakeTlsStream> for MidHandshakeTlsStream {
    fn from(mid: NativeTlsMidHandshakeTlsStream) -> Self {
        Self::NativeTls(mid)
    }
}

impl From<NativeTlsHandshakeError> for HandshakeError {
    fn from(error: NativeTlsHandshakeError) -> Self {
        match error {
            native_tls::HandshakeError::WouldBlock(mid) => Self::WouldBlock(mid.into()),
            native_tls::HandshakeError::Failure(failure) => {
                Self::Failure(io::Error::other(failure))
            }
        }
    }
}
