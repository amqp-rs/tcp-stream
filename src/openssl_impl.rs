use crate::{
    HandshakeError, HandshakeResult, Identity, MidHandshakeTlsStream, TLSConfig, TcpStream,
};

use openssl::x509::X509;
use std::io;

/// Reexport openssl's `TlsConnector`
pub use openssl::ssl::{SslConnector as OpenSslConnector, SslMethod as OpenSslMethod};

/// A `TcpStream` wrapped by openssl
pub type OpenSslStream = openssl::ssl::SslStream<TcpStream>;

/// A `MidHandshakeTlsStream` from openssl
pub type OpenSslMidHandshakeTlsStream = openssl::ssl::MidHandshakeSslStream<TcpStream>;

/// A `HandshakeError` from openssl
pub type OpenSslHandshakeError = openssl::ssl::HandshakeError<TcpStream>;

/// An `ErrorStack` from openssl
pub type OpenSslErrorStack = openssl::error::ErrorStack;

fn openssl_connector(
    config: TLSConfig<'_, '_, '_>,
) -> io::Result<OpenSslConnector> {
    let mut builder = OpenSslConnector::builder(OpenSslMethod::tls())?;
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

pub(crate) fn into_openssl_impl(
    s: TcpStream,
    domain: &str,
    config: TLSConfig<'_, '_, '_>,
) -> HandshakeResult {
    s.into_openssl(&openssl_connector(config)?, domain)
}

impl From<OpenSslStream> for TcpStream {
    fn from(s: OpenSslStream) -> Self {
        TcpStream::OpenSsl(Box::new(s))
    }
}

impl From<OpenSslMidHandshakeTlsStream> for MidHandshakeTlsStream {
    fn from(mid: OpenSslMidHandshakeTlsStream) -> Self {
        MidHandshakeTlsStream::Openssl(mid)
    }
}

impl From<OpenSslHandshakeError> for HandshakeError {
    fn from(error: OpenSslHandshakeError) -> Self {
        match error {
            openssl::ssl::HandshakeError::WouldBlock(mid) => HandshakeError::WouldBlock(mid.into()),
            openssl::ssl::HandshakeError::Failure(failure) => {
                HandshakeError::Failure(io::Error::other(failure.into_error()))
            }
            openssl::ssl::HandshakeError::SetupFailure(failure) => failure.into(),
        }
    }
}

impl From<OpenSslErrorStack> for HandshakeError {
    fn from(error: OpenSslErrorStack) -> Self {
        Self::Failure(error.into())
    }
}
