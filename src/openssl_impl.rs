use crate::{
    HandshakeError, HandshakeResult, Identity, MidHandshakeTlsStream, StdTcpStream, TLSConfig,
    TcpStream,
};

#[cfg(feature = "openssl-futures")]
use {
    crate::AsyncTcpStream,
    futures_io::{AsyncRead, AsyncWrite},
};

use openssl::x509::{X509, X509VerifyResult};
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

/// Load certificates that `crate::pem` decoded. OpenSSL's PEM reader gets no
/// password callback from `X509::stack_from_pem`, so it would prompt for an
/// encrypted object.
fn x509_certificates(certs: &[impl AsRef<[u8]>]) -> io::Result<Vec<X509>> {
    certs
        .iter()
        .map(|cert| X509::from_der(cert.as_ref()).map_err(crate::invalid_data))
        .collect()
}

/// Put the extra certificates of a PKCS#12 bundle in leaf-to-root order.
///
/// `PKCS12_parse` reverses them before OpenSSL 3.0 and in LibreSSL, but other
/// libraries reporting old versions keep them in order, so follow the issuers.
fn order_pkcs12_chain(cert: Option<&X509>, chain: &mut [X509]) {
    let issued = |issuer: &X509, subject: &X509| issuer.issued(subject) == X509VerifyResult::OK;
    if let (Some(cert), [first, .., last]) = (cert, &*chain)
        && !issued(first, cert)
        && issued(last, cert)
    {
        chain.reverse();
    }
}

/// Configure a client identity. Its errors describe the identity, so the caller
/// reports them all as `InvalidData`.
fn set_identity(
    builder: &mut openssl::ssl::SslContextBuilder,
    cert: &X509,
    pkey: &openssl::pkey::PKeyRef<openssl::pkey::Private>,
    chain: Vec<X509>,
) -> Result<(), OpensslErrorStack> {
    builder.set_certificate(cert)?;
    // OpenSSL can report a key that does not match the certificate here or in
    // the explicit check.
    builder.set_private_key(pkey)?;
    builder.check_private_key()?;
    for cert in chain {
        builder.add_extra_chain_cert(cert)?;
    }
    Ok(())
}

fn openssl_connector(config: TLSConfig<'_, '_, '_>) -> io::Result<OpensslConnector> {
    let mut builder = OpensslConnector::builder(OpensslMethod::tls())?;
    if let Some(identity) = config.identity {
        let (cert, pkey, chain) = match identity {
            Identity::PKCS8 { pem, key } => {
                // An explicit empty passphrase disables OpenSSL's terminal
                // password prompt. This identity format has no password field.
                let pkey = openssl::pkey::PKey::private_key_from_pem_passphrase(key, b"")
                    .map_err(crate::invalid_data)?;
                let mut chain =
                    x509_certificates(&crate::pem::identity_certificates(pem)?)?.into_iter();
                let cert = chain.next();
                (cert, Some(pkey), chain.collect())
            }
            Identity::PKCS12 { der, password } => {
                crate::validate_pkcs12_password(password)?;
                let openssl::pkcs12::ParsedPkcs12_2 { pkey, cert, ca } =
                    openssl::pkcs12::Pkcs12::from_der(der)
                        .and_then(|pkcs12| pkcs12.parse2(password))
                        .map_err(crate::invalid_data)?;
                let mut chain: Vec<_> = ca.into_iter().flatten().collect();
                order_pkcs12_chain(cert.as_ref(), &mut chain);
                (cert, pkey, chain)
            }
        };
        // OpenSSL accepts either component on its own. An explicit client
        // identity must contain both, so fail during configuration instead of
        // silently connecting without the requested client authentication.
        let cert = cert.ok_or_else(|| crate::invalid_data("client identity has no certificate"))?;
        let pkey = pkey.ok_or_else(|| crate::invalid_data("client identity has no private key"))?;
        set_identity(&mut builder, &cert, &pkey, chain).map_err(crate::invalid_data)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{CERT_CHAIN, PRIVATE_KEY, ROOT_CERT};

    #[test]
    fn rejects_invalid_pkcs12_identities() {
        crate::tests::check_pkcs12_rejections(openssl_connector);
    }

    #[test]
    fn encrypted_pkcs8_identity_does_not_prompt() {
        if !crate::tests::password_prompt_test_child(
            "openssl_impl::tests::encrypted_pkcs8_identity_does_not_prompt",
        ) {
            return;
        }
        let key = openssl::pkey::PKey::private_key_from_pem(PRIVATE_KEY).unwrap();
        let encrypted = key
            .private_key_to_pem_pkcs8_passphrase(
                openssl::symm::Cipher::aes_256_cbc(),
                b"fixture password",
            )
            .unwrap();
        let error = openssl_connector(TLSConfig {
            identity: Some(Identity::PKCS8 {
                pem: CERT_CHAIN,
                key: &encrypted,
            }),
            cert_chain: None,
        })
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn encrypted_pem_certificates_do_not_prompt() {
        if !crate::tests::password_prompt_test_child(
            "openssl_impl::tests::encrypted_pem_certificates_do_not_prompt",
        ) {
            return;
        }
        let encrypted = std::str::from_utf8(CERT_CHAIN).unwrap().replacen(
            "-----BEGIN CERTIFICATE-----\n",
            "-----BEGIN CERTIFICATE-----\nProc-Type: 4,ENCRYPTED\n\
             DEK-Info: AES-128-CBC,00000000000000000000000000000000\n\n",
            1,
        );
        let identity = |pem: &str| {
            openssl_connector(TLSConfig {
                identity: Some(Identity::PKCS8 {
                    pem: pem.as_bytes(),
                    key: PRIVATE_KEY,
                }),
                cert_chain: None,
            })
            .unwrap_err()
        };
        // OpenSSL also recognizes these boundaries, which other parsers may not.
        for pem in [
            encrypted.clone(),
            encrypted.replacen("-----\nProc-Type", "-----\x0b\nProc-Type", 1),
            format!("\u{feff}{encrypted}"),
        ] {
            assert_eq!(
                identity(&pem).to_string(),
                crate::pem::invalid_identity_chain().to_string()
            );
        }
        // A boundary must start a line, so this leaf is skipped and the next
        // certificate does not match the key.
        let error = identity(&format!("{}{encrypted}", "x".repeat(254)));
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn certificates_next_to_an_encrypted_key_do_not_prompt() {
        if !crate::tests::password_prompt_test_child(
            "openssl_impl::tests::certificates_next_to_an_encrypted_key_do_not_prompt",
        ) {
            return;
        }
        let key = openssl::pkey::PKey::private_key_from_pem(PRIVATE_KEY).unwrap();
        let encrypted = key
            .rsa()
            .unwrap()
            .private_key_to_pem_passphrase(openssl::symm::Cipher::aes_128_cbc(), b"password")
            .unwrap();
        let pem = [CERT_CHAIN, &encrypted].concat();
        openssl_connector(TLSConfig {
            identity: Some(Identity::PKCS8 {
                pem: &pem,
                key: PRIVATE_KEY,
            }),
            cert_chain: None,
        })
        .unwrap();
    }

    #[test]
    fn orders_pkcs12_chains_from_the_leaf() {
        let certs = X509::stack_from_pem(CERT_CHAIN).unwrap();
        assert!(certs.len() >= 3);
        let expected = certs[1..].to_vec();
        for mut chain in [expected.clone(), expected.iter().rev().cloned().collect()] {
            order_pkcs12_chain(Some(&certs[0]), &mut chain);
            assert_eq!(chain, expected);
        }
    }

    #[test]
    fn rejects_pkcs8_identity_without_a_certificate() {
        assert!(
            openssl_connector(TLSConfig {
                identity: Some(Identity::PKCS8 {
                    pem: &[],
                    key: PRIVATE_KEY,
                }),
                cert_chain: None,
            })
            .is_err(),
            "accepted a client identity without a certificate"
        );
    }

    #[test]
    fn rejects_identity_with_a_mismatched_private_key() {
        let error = openssl_connector(TLSConfig {
            identity: Some(Identity::PKCS8 {
                pem: ROOT_CERT.as_bytes(),
                key: PRIVATE_KEY,
            }),
            cert_chain: None,
        })
        .expect_err("accepted the leaf's private key with a different certificate");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn rejects_pkcs12_identity_without_a_private_key() {
        let certs = X509::stack_from_pem(CERT_CHAIN).unwrap();
        let der = openssl::pkcs12::Pkcs12::builder()
            .cert(&certs[0])
            .build2("test password")
            .unwrap()
            .to_der()
            .unwrap();
        assert!(
            openssl::pkcs12::Pkcs12::from_der(&der)
                .unwrap()
                .parse2("test password")
                .unwrap()
                .pkey
                .is_none()
        );
        assert!(
            openssl_connector(TLSConfig {
                identity: Some(Identity::PKCS12 {
                    der: &der,
                    password: "test password",
                }),
                cert_chain: None,
            })
            .is_err(),
            "accepted a client identity without a private key"
        );
    }

    #[test]
    fn rejects_pkcs12_identity_without_a_certificate() {
        let key = openssl::pkey::PKey::private_key_from_pem(PRIVATE_KEY).unwrap();
        let der = openssl::pkcs12::Pkcs12::builder()
            .pkey(&key)
            .build2("test password")
            .unwrap()
            .to_der()
            .unwrap();
        assert!(
            openssl::pkcs12::Pkcs12::from_der(&der)
                .unwrap()
                .parse2("test password")
                .unwrap()
                .cert
                .is_none()
        );
        assert!(
            openssl_connector(TLSConfig {
                identity: Some(Identity::PKCS12 {
                    der: &der,
                    password: "test password",
                }),
                cert_chain: None,
            })
            .is_err(),
            "accepted a client identity without a certificate"
        );
    }

    fn chain_der(connector: &OpensslConnector) -> Vec<Vec<u8>> {
        connector
            .context()
            .extra_chain_certs()
            .iter()
            .map(|cert| cert.to_der().unwrap())
            .collect()
    }

    /// The DER of the fixture chain's extra certificates, which the identity
    /// sends after its leaf.
    fn expected_chain_der(certs: &[X509]) -> Vec<Vec<u8>> {
        certs[1..]
            .iter()
            .map(|cert| cert.to_der().unwrap())
            .collect()
    }

    #[test]
    fn preserves_pkcs8_certificate_chain_order() {
        let certs = X509::stack_from_pem(CERT_CHAIN).unwrap();
        let expected = expected_chain_der(&certs);
        let connector = openssl_connector(TLSConfig {
            identity: Some(Identity::PKCS8 {
                pem: CERT_CHAIN,
                key: PRIVATE_KEY,
            }),
            cert_chain: None,
        })
        .unwrap();
        assert_eq!(chain_der(&connector), expected);
    }

    #[test]
    fn preserves_pkcs12_certificate_chain_order() {
        let certs = X509::stack_from_pem(CERT_CHAIN).unwrap();
        let key = openssl::pkey::PKey::private_key_from_pem(PRIVATE_KEY).unwrap();
        let mut chain = openssl::stack::Stack::new().unwrap();
        for cert in &certs[1..] {
            chain.push(cert.clone()).unwrap();
        }
        let der = openssl::pkcs12::Pkcs12::builder()
            .name("test identity")
            .pkey(&key)
            .cert(&certs[0])
            .ca(chain)
            .build2("test password")
            .unwrap()
            .to_der()
            .unwrap();
        let expected = expected_chain_der(&certs);
        let connector = openssl_connector(TLSConfig {
            identity: Some(Identity::PKCS12 {
                der: &der,
                password: "test password",
            }),
            cert_chain: None,
        })
        .unwrap();
        assert_eq!(chain_der(&connector), expected);
    }
}
