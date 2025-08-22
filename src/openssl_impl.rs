use crate::{
    HandshakeError, HandshakeResult, Identity, MidHandshakeTlsStream, StdTcpStream, TLSConfig,
    TcpStream,
};

#[cfg(feature = "openssl-futures")]
use {
    crate::AsyncTcpStream,
    futures_io::{AsyncRead, AsyncWrite},
};

use openssl::x509::X509;
use std::io;

/// Reexport openssl's `TlsConnector`
pub use openssl::ssl::{SslConnector as OpensslConnector, SslMethod as OpensslMethod};

/// A `TcpStream` wrapped by openssl
pub type OpensslStream = openssl::ssl::SslStream<StdTcpStream>;

/// A `MidHandshakeTlsStream` from openssl
pub type OpensslMidHandshakeTlsStream = openssl::ssl::MidHandshakeSslStream<StdTcpStream>;

/// A `HandshakeError` from openssl
pub type OpensslHandshakeError = openssl::ssl::HandshakeError<StdTcpStream>;

/// An `ErrorStack` from openssl
pub type OpensslErrorStack = openssl::error::ErrorStack;

#[cfg(feature = "openssl-futures")]
/// An async `TcpStream` wrapped by openssl
pub type OpensslAsyncStream<S> = async_openssl::SslStream<S>;

fn openssl_connector(config: TLSConfig<'_, '_, '_>) -> io::Result<OpensslConnector> {
    let mut builder = OpensslConnector::builder(OpensslMethod::tls())?;
    if let Some(identity) = config.identity {
        let (cert, pkey, chain) = match identity {
            Identity::PKCS8 { pem, key } => {
                let pkey = openssl::pkey::PKey::private_key_from_pem(key)?;
                let mut chain = openssl::x509::X509::stack_from_pem(pem)?.into_iter();
                let cert = chain.next();
                (cert, Some(pkey), Some(chain.collect()))
            }
            Identity::PKCS12 { der, password } => {
                let mut openssl_identity =
                    openssl::pkcs12::Pkcs12::from_der(der)?.parse2(password)?;
                (
                    openssl_identity.cert,
                    openssl_identity.pkey,
                    openssl_identity
                        .ca
                        .take()
                        .map(|stack| stack.into_iter().collect::<Vec<_>>()),
                )
            }
        };
        if let Some(cert) = cert.as_ref() {
            builder.set_certificate(cert)?;
        }
        if let Some(pkey) = pkey.as_ref() {
            builder.set_private_key(pkey)?;
        }
        if let Some(chain) = chain.as_ref() {
            for cert in chain.iter().rev() {
                builder.add_extra_chain_cert(cert.to_owned())?;
            }
        }
    }
    if let Some(cert_chain) = config.cert_chain.as_ref() {
        for cert in X509::stack_from_pem(cert_chain.as_bytes())?.drain(..).rev() {
            builder.cert_store_mut().add_cert(cert)?;
        }
    }
    Ok(builder.build())
}

#[allow(dead_code)]
pub(crate) fn into_openssl_impl(
    s: TcpStream,
    domain: &str,
    config: TLSConfig<'_, '_, '_>,
) -> HandshakeResult {
    s.into_openssl(&openssl_connector(config)?, domain)
}

#[cfg(feature = "openssl-futures")]
#[allow(dead_code)]
pub(crate) async fn into_openssl_impl_async<S: AsyncRead + AsyncWrite + Send + Unpin + 'static>(
    s: AsyncTcpStream<S>,
    domain: &str,
    config: TLSConfig<'_, '_, '_>,
) -> io::Result<AsyncTcpStream<S>> {
    s.into_openssl(&openssl_connector(config)?, domain).await
}

impl From<OpensslStream> for TcpStream {
    fn from(s: OpensslStream) -> Self {
        Self::Openssl(s)
    }
}

impl From<OpensslMidHandshakeTlsStream> for MidHandshakeTlsStream {
    fn from(mid: OpensslMidHandshakeTlsStream) -> Self {
        Self::Openssl(mid)
    }
}

impl From<OpensslHandshakeError> for HandshakeError {
    fn from(error: OpensslHandshakeError) -> Self {
        match error {
            openssl::ssl::HandshakeError::WouldBlock(mid) => Self::WouldBlock(mid.into()),
            openssl::ssl::HandshakeError::Failure(failure) => {
                Self::Failure(io::Error::other(failure.into_error()))
            }
            openssl::ssl::HandshakeError::SetupFailure(failure) => failure.into(),
        }
    }
}

impl From<OpensslErrorStack> for HandshakeError {
    fn from(error: OpensslErrorStack) -> Self {
        Self::Failure(error.into())
    }
}
