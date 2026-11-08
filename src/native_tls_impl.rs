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

#[cfg(not(all(target_vendor = "apple", not(target_os = "macos"))))]
fn invalid_pkcs8_key() -> io::Error {
    crate::invalid_data("PKCS#8 identity requires an unencrypted PKCS#8 PRIVATE KEY PEM object")
}

#[cfg(not(all(target_vendor = "apple", not(target_os = "macos"))))]
fn pkcs8_identity_documents(pem: &[u8], key: &[u8]) -> io::Result<(String, pkcs8::SecretDocument)> {
    use pkcs8::{
        PrivateKeyInfoRef, SecretDocument,
        der::pem::{LineEnding, encode_string},
    };

    let key_der = crate::pem::pem_private_key(key).ok_or_else(invalid_pkcs8_key)?;
    // The PEM label does not validate the DER: OpenSSL can recognize an
    // EncryptedPrivateKeyInfo even under PRIVATE KEY and ask for a password.
    // Decode the complete unencrypted structure, including its DER boundary.
    let key = PrivateKeyInfoRef::try_from(key_der.as_slice())
        .and_then(SecretDocument::try_from)
        .map_err(|_| invalid_pkcs8_key())?;

    let mut cert_pem = String::new();
    for cert in crate::pem::identity_certificates(pem)? {
        Certificate::from_der(&cert).map_err(|_| crate::pem::invalid_identity_chain())?;
        cert_pem.push_str(
            &encode_string("CERTIFICATE", LineEnding::LF, &cert)
                .map_err(|_| crate::pem::invalid_identity_chain())?,
        );
    }
    Ok((cert_pem, key))
}

#[cfg(not(all(target_vendor = "apple", not(target_os = "macos"))))]
fn pkcs8_identity(pem: &[u8], key: &[u8]) -> io::Result<native_tls::Identity> {
    let (cert_pem, key) = pkcs8_identity_documents(pem, key)?;
    let key = key
        .to_pem("PRIVATE KEY", pkcs8::der::pem::LineEnding::LF)
        .map_err(|_| invalid_pkcs8_key())?;
    // macOS imports every object in the supplied PEM. Pass only the validated
    // key and certificates so appended objects cannot trigger decryption UI.
    // SecretDocument's PEM buffer is zeroized when it is dropped. Copies made by
    // the PEM parser and by the TLS library are outside this function's control.
    native_tls::Identity::from_pkcs8(cert_pem.as_bytes(), key.as_bytes())
        .map_err(crate::invalid_data)
}

fn native_tls_connector_builder(
    config: TLSConfig<'_, '_, '_>,
) -> io::Result<NativeTlsConnectorBuilder> {
    let mut builder = NativeTlsConnector::builder();
    if let Some(identity) = config.identity {
        let native_identity = match identity {
            Identity::PKCS8 { pem, key } => {
                #[cfg(all(target_vendor = "apple", not(target_os = "macos")))]
                {
                    let _ = (pem, key);
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "native-tls PKCS#8 identities are unsupported on this platform; use PKCS#12",
                    ));
                }
                #[cfg(not(all(target_vendor = "apple", not(target_os = "macos"))))]
                {
                    pkcs8_identity(pem, key)?
                }
            }
            Identity::PKCS12 { der, password } => {
                crate::validate_pkcs12_password(password)?;
                native_tls::Identity::from_pkcs12(der, password).map_err(crate::invalid_data)?
            }
        };
        builder.identity(native_identity);
    }
    if let Some(cert_chain) = config.cert_chain {
        for cert in crate::pem::custom_roots(cert_chain)? {
            builder.add_root_certificate(
                Certificate::from_der(&cert[..]).map_err(crate::invalid_data)?,
            );
        }
    }
    Ok(builder)
}

pub(crate) fn native_tls_connector(
    config: TLSConfig<'_, '_, '_>,
) -> io::Result<NativeTlsConnector> {
    let has_identity = config.identity.is_some();
    build_connector(&native_tls_connector_builder(config)?, has_identity)
}

/// Build a connector. With an identity configured, report a failure as
/// `InvalidData`, since the identity is its likely cause: the roots were
/// already validated. Otherwise the failure comes from the TLS library.
fn build_connector(
    builder: &NativeTlsConnectorBuilder,
    has_identity: bool,
) -> io::Result<NativeTlsConnector> {
    builder.build().map_err(|err| {
        if has_identity {
            crate::invalid_data(err)
        } else {
            io::Error::other(err)
        }
    })
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
    let has_identity = config.identity.is_some();
    let builder = native_tls_connector_builder(config)?;
    // async-native-tls builds the connector while connecting, where a failure
    // looks like a handshake error. Report one here as the sync upgrade does.
    build_connector(&builder, has_identity)?;
    s.into_native_tls(builder, domain).await
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_encrypted_pkcs8_identity_does_not_prompt() {
        if !crate::tests::password_prompt_test_child(
            "native_tls_impl::tests::legacy_encrypted_pkcs8_identity_does_not_prompt",
        ) {
            return;
        }
        // Legacy headers can hide encryption under a PRIVATE KEY label.
        assert_invalid_pkcs8_identity(
            crate::tests::CERT_CHAIN,
            include_bytes!("../tests/fixtures/legacy-encrypted-key.pem"),
        );
    }

    #[test]
    fn encrypted_pkcs8_der_does_not_prompt() {
        if !crate::tests::password_prompt_test_child(
            "native_tls_impl::tests::encrypted_pkcs8_der_does_not_prompt",
        ) {
            return;
        }
        let encrypted = crate::tests::ENCRYPTED_KEY;
        let mislabeled = encrypted.replace("ENCRYPTED PRIVATE KEY", "PRIVATE KEY");
        let key = crate::tests::pkcs8_key();
        let mut trailing_der = key.secret_pkcs8_der().to_vec();
        trailing_der.extend_from_slice(&[0x30, 0x00]);
        let trailing_der = pkcs8::der::pem::encode_string(
            "PRIVATE KEY",
            pkcs8::der::pem::LineEnding::LF,
            &trailing_der,
        )
        .unwrap();
        // The first malformed object must fail before a decoder can skip it
        // and discover encrypted DER or an encrypted PEM object after it.
        let empty_then_encrypted =
            format!("-----BEGIN PRIVATE KEY-----\nMAA=\n-----END PRIVATE KEY-----\n{encrypted}");
        for key in [encrypted, &mislabeled, &trailing_der, &empty_then_encrypted] {
            assert_invalid_pkcs8_identity(crate::tests::CERT_CHAIN, key.as_bytes());
        }
        let encrypted_cert = encrypted.replace("ENCRYPTED PRIVATE KEY", "CERTIFICATE");
        let chain = [crate::tests::CERT_CHAIN, encrypted_cert.as_bytes()].concat();
        assert_invalid_pkcs8_identity(&chain, crate::tests::PRIVATE_KEY);
    }

    #[cfg(not(all(target_vendor = "apple", not(target_os = "macos"))))]
    #[test]
    fn extra_pem_objects_do_not_reach_the_pkcs8_importer() {
        if !crate::tests::password_prompt_test_child(
            "native_tls_impl::tests::extra_pem_objects_do_not_reach_the_pkcs8_importer",
        ) {
            return;
        }
        let encrypted = crate::tests::ENCRYPTED_KEY;
        let mislabeled = encrypted.replace("ENCRYPTED PRIVATE KEY", "PRIVATE KEY");
        for extra in [encrypted.as_bytes(), mislabeled.as_bytes()] {
            let key = [crate::tests::PRIVATE_KEY, extra].concat();
            let chain = [extra, crate::tests::CERT_CHAIN, extra].concat();
            // Linux's importer already ignores extra objects. Inspect the
            // prepared data too so this test protects macOS on every host.
            let (cert_pem, document) = pkcs8_identity_documents(&chain, &key).unwrap();
            assert_eq!(
                document.as_bytes(),
                crate::tests::pkcs8_key().secret_pkcs8_der()
            );
            assert_eq!(
                crate::tests::certificates(cert_pem.as_bytes()),
                crate::tests::certificates(crate::tests::CERT_CHAIN)
            );
            assert!(!cert_pem.contains("PRIVATE KEY"));
            native_tls_connector_builder(TLSConfig {
                identity: Some(Identity::PKCS8 {
                    pem: &chain,
                    key: &key,
                }),
                cert_chain: None,
            })
            .unwrap();
        }
    }

    #[cfg(not(all(target_vendor = "apple", not(target_os = "macos"))))]
    #[test]
    fn normalizes_legacy_certificate_labels() {
        let (chain, certs) = crate::pem::tests::legacy_chain();
        let (cert_pem, _) =
            pkcs8_identity_documents(chain.as_bytes(), crate::tests::PRIVATE_KEY).unwrap();
        assert_eq!(crate::tests::certificates(cert_pem.as_bytes()), certs);
        native_tls_connector_builder(TLSConfig {
            identity: Some(Identity::PKCS8 {
                pem: chain.as_bytes(),
                key: crate::tests::PRIVATE_KEY,
            }),
            cert_chain: None,
        })
        .unwrap();
    }

    fn assert_invalid_pkcs8_identity(pem: &[u8], key: &[u8]) {
        let config = || TLSConfig {
            identity: Some(Identity::PKCS8 { pem, key }),
            cert_chain: None,
        };
        let error = native_tls_connector_builder(config())
            .map(drop)
            .expect_err("accepted an encrypted PKCS#8 identity");
        #[cfg(all(target_vendor = "apple", not(target_os = "macos")))]
        let expected = io::ErrorKind::Unsupported;
        #[cfg(not(all(target_vendor = "apple", not(target_os = "macos"))))]
        let expected = io::ErrorKind::InvalidData;
        assert_eq!(error.kind(), expected);

        #[cfg(feature = "native-tls-futures")]
        {
            use std::task::Poll;
            let result = crate::tests::poll_once(into_native_tls_impl_async(
                AsyncTcpStream::Plain(crate::tests::NoIo),
                "localhost",
                config(),
            ));
            assert!(matches!(result, Poll::Ready(Err(error)) if error.kind() == expected));
        }
    }

    #[test]
    fn rejects_invalid_pkcs12_identities() {
        crate::tests::check_pkcs12_rejections(native_tls_connector_builder);
    }

    #[cfg(all(target_vendor = "apple", not(target_os = "macos")))]
    #[test]
    fn pkcs8_identity_returns_unsupported() {
        let error = native_tls_connector_builder(TLSConfig {
            identity: Some(Identity::PKCS8 {
                pem: crate::tests::CERT_CHAIN,
                key: crate::tests::PRIVATE_KEY,
            }),
            cert_chain: None,
        })
        .map(drop)
        .expect_err("accepted unsupported PKCS#8 identity");
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    }

    #[cfg(not(all(target_vendor = "apple", not(target_os = "macos"))))]
    #[test]
    fn accepts_unencrypted_pkcs8_identity() {
        native_tls_connector_builder(TLSConfig {
            identity: Some(Identity::PKCS8 {
                pem: crate::tests::CERT_CHAIN,
                key: crate::tests::PRIVATE_KEY,
            }),
            cert_chain: None,
        })
        .unwrap();
    }

    #[test]
    fn validates_custom_roots() {
        crate::tests::check_custom_roots(native_tls_connector_builder);
        native_tls_connector_builder(TLSConfig {
            identity: Some(Identity::PKCS12 {
                der: crate::tests::PKCS12_IDENTITY,
                password: crate::tests::PKCS12_PASSWORD,
            }),
            cert_chain: Some(crate::tests::ROOT_CERT),
        })
        .unwrap();
    }
}
