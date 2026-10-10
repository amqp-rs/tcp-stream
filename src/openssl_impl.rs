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
                let mut chain = X509::stack_from_pem(pem)?.into_iter();
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
        if cert.is_some() && pkey.is_some() {
            // Catch a mismatched certificate/key pair here, where we can
            // report it, instead of failing later with an opaque handshake
            // error.
            builder.check_private_key()?;
        }
        if let Some(chain) = chain.as_ref() {
            // `add_extra_chain_cert` appends to the Certificate message in
            // call order, and TLS wants the chain ordered from the leaf
            // towards the root (RFC 5246 section 7.4.2), with each entry
            // certifying the one before it. Both identity formats already
            // hand us the intermediates in that order, so send them as-is.
            for cert in chain {
                builder.add_extra_chain_cert(cert.to_owned())?;
            }
        }
    }
    if let Some(cert_chain) = config.cert_chain.as_ref() {
        // A certificate store is an unordered set, so insertion order is
        // irrelevant here.
        for cert in X509::stack_from_pem(cert_chain.as_bytes())? {
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
    use crate::TcpStream;

    use openssl::{
        asn1::Asn1Time,
        bn::{BigNum, MsbOption},
        ec::{EcGroup, EcKey},
        hash::MessageDigest,
        nid::Nid,
        pkey::{PKey, PKeyRef, Private},
        ssl::{SslAcceptor, SslMethod, SslVerifyMode},
        stack::Stack,
        x509::{
            X509, X509Name, X509Ref,
            extension::{BasicConstraints, KeyUsage, SubjectAlternativeName},
        },
    };
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
    };

    fn key() -> PKey<Private> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()
    }

    /// Issues a certificate for `cn`, self-signed when `issuer` is `None`.
    fn cert(
        cn: &str,
        key: &PKeyRef<Private>,
        issuer: Option<(&X509Ref, &PKeyRef<Private>)>,
        ca: bool,
    ) -> X509 {
        let mut name = X509Name::builder().unwrap();
        name.append_entry_by_nid(Nid::COMMONNAME, cn).unwrap();
        let name = name.build();

        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        let mut serial = BigNum::new().unwrap();
        serial.rand(159, MsbOption::MAYBE_ZERO, false).unwrap();
        builder
            .set_serial_number(&serial.to_asn1_integer().unwrap())
            .unwrap();
        builder.set_subject_name(&name).unwrap();
        builder
            .set_issuer_name(issuer.map_or(&name, |(ca, _)| ca.subject_name()))
            .unwrap();
        builder.set_pubkey(key).unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        if ca {
            builder
                .append_extension(BasicConstraints::new().critical().ca().build().unwrap())
                .unwrap();
            builder
                .append_extension(
                    KeyUsage::new()
                        .critical()
                        .key_cert_sign()
                        .crl_sign()
                        .build()
                        .unwrap(),
                )
                .unwrap();
        } else {
            let san = SubjectAlternativeName::new()
                .dns(cn)
                .build(&builder.x509v3_context(issuer.map(|(ca, _)| ca), None))
                .unwrap();
            builder.append_extension(san).unwrap();
        }
        builder
            .sign(issuer.map_or(key, |(_, key)| key), MessageDigest::sha256())
            .unwrap();
        builder.build()
    }

    /// A `root -> intermediate -> leaf` client chain plus a server certificate
    /// issued by the same root.
    struct Pki {
        root: X509,
        intermediate: X509,
        leaf: X509,
        leaf_key: PKey<Private>,
        server: X509,
        server_key: PKey<Private>,
    }

    impl Pki {
        fn new() -> Self {
            let (root_key, intermediate_key, leaf_key, server_key) = (key(), key(), key(), key());
            let root = cert("tcp-stream-test-root", &root_key, None, true);
            let intermediate = cert(
                "tcp-stream-test-intermediate",
                &intermediate_key,
                Some((&root, &root_key)),
                true,
            );
            let leaf = cert(
                "tcp-stream-test-leaf",
                &leaf_key,
                Some((&intermediate, &intermediate_key)),
                false,
            );
            let server = cert("localhost", &server_key, Some((&root, &root_key)), false);
            Self {
                root,
                intermediate,
                leaf,
                leaf_key,
                server,
                server_key,
            }
        }

        fn root_pem(&self) -> String {
            String::from_utf8(self.root.to_pem().unwrap()).unwrap()
        }

        /// Names the certificates of this PKI, so assertion failures are
        /// readable rather than a wall of DER.
        fn label(&self, der: &[u8]) -> String {
            for (name, cert) in [
                ("leaf", &self.leaf),
                ("intermediate", &self.intermediate),
                ("root", &self.root),
            ] {
                if cert.to_der().unwrap() == der {
                    return name.to_owned();
                }
            }
            "<unknown>".to_owned()
        }
    }

    /// Completes one handshake against an in-process OpenSSL server that asks
    /// for a client certificate, and reports the chain the client sent, in
    /// wire order, by label.
    fn client_chain_sent_with(pki: &Pki, connector: &OpensslConnector) -> Vec<String> {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let (server_cert, server_key, root) =
            (pki.server.clone(), pki.server_key.clone(), pki.root.clone());
        let server = thread::spawn(move || {
            let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
            acceptor.set_certificate(&server_cert).unwrap();
            acceptor.set_private_key(&server_key).unwrap();
            acceptor.cert_store_mut().add_cert(root).unwrap();
            // Request a client certificate but accept whatever arrives, so the
            // test observes exactly what was put on the wire.
            acceptor.set_verify_callback(SslVerifyMode::PEER, |_, _| true);
            let (socket, _) = listener.accept().unwrap();
            let stream = acceptor.build().accept(socket).unwrap();

            // Server-side, the leaf is reported separately from the rest of
            // the chain, so stitch the two back together in wire order.
            let mut chain = Vec::new();
            if let Some(leaf) = stream.ssl().peer_certificate() {
                chain.push(leaf.to_der().unwrap());
            }
            if let Some(rest) = stream.ssl().peer_cert_chain() {
                chain.extend(rest.iter().map(|cert| cert.to_der().unwrap()));
            }
            chain
        });

        let mut stream = TcpStream::connect(addr)
            .unwrap()
            .into_openssl(connector, "localhost")
            .unwrap();
        stream.flush().unwrap();

        server
            .join()
            .unwrap()
            .iter()
            .map(|der| pki.label(der))
            .collect()
    }

    #[test]
    fn pkcs8_identity_chain_is_sent_leaf_first() {
        let pki = Pki::new();
        // A PEM bundle in the conventional leaf-to-root order. It needs more
        // than one issuer for the assertion below to be sensitive to the
        // order the chain is sent in.
        let mut pem = pki.leaf.to_pem().unwrap();
        pem.extend_from_slice(&pki.intermediate.to_pem().unwrap());
        pem.extend_from_slice(&pki.root.to_pem().unwrap());
        let key = pki.leaf_key.private_key_to_pem_pkcs8().unwrap();
        let root_pem = pki.root_pem();

        let connector = openssl_connector(TLSConfig {
            identity: Some(Identity::PKCS8 {
                pem: &pem,
                key: &key,
            }),
            cert_chain: Some(&root_pem),
        })
        .unwrap();

        assert_eq!(
            client_chain_sent_with(&pki, &connector),
            ["leaf", "intermediate", "root"],
        );
    }

    #[test]
    fn pkcs12_identity_chain_is_sent_leaf_first() {
        let pki = Pki::new();
        let mut ca = Stack::new().unwrap();
        ca.push(pki.intermediate.clone()).unwrap();
        ca.push(pki.root.clone()).unwrap();

        let mut pkcs12 = openssl::pkcs12::Pkcs12::builder();
        pkcs12
            .name("tcp-stream-test")
            .pkey(&pki.leaf_key)
            .cert(&pki.leaf)
            .ca(ca);
        let der = pkcs12.build2("password").unwrap().to_der().unwrap();
        let root_pem = pki.root_pem();

        let connector = openssl_connector(TLSConfig {
            identity: Some(Identity::PKCS12 {
                der: &der,
                password: "password",
            }),
            cert_chain: Some(&root_pem),
        })
        .unwrap();

        assert_eq!(
            client_chain_sent_with(&pki, &connector),
            ["leaf", "intermediate", "root"],
        );
    }

    /// An already-encrypted stream cannot be upgraded a second time.
    #[test]
    fn upgrading_twice_is_refused() {
        let pki = Pki::new();
        let root_pem = pki.root_pem();
        let connector = openssl_connector(TLSConfig {
            identity: None,
            cert_chain: Some(&root_pem),
        })
        .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (server_cert, server_key) = (pki.server.clone(), pki.server_key.clone());
        let server = thread::spawn(move || {
            let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
            acceptor.set_certificate(&server_cert).unwrap();
            acceptor.set_private_key(&server_key).unwrap();
            let (socket, _) = listener.accept().unwrap();
            let mut stream = acceptor.build().accept(socket).unwrap();
            stream.flush().ok();
            // Hold the connection open until the client is done with it.
            let mut buf = [0; 1];
            let _ = stream.read(&mut buf);
        });

        let stream = TcpStream::connect(addr)
            .unwrap()
            .into_openssl(&connector, "localhost")
            .unwrap();
        // The second upgrade consumes and drops the stream, which lets the
        // server thread's pending read complete.
        let err = stream
            .into_openssl(&connector, "localhost")
            .expect_err("a TLS stream must not be upgraded twice")
            .into_mid_handshake_tls_stream()
            .expect_err("the refusal is a permanent failure, not a WouldBlock");
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);

        server.join().unwrap();
    }

    #[test]
    fn mismatched_certificate_and_key_are_rejected() {
        let pki = Pki::new();
        // The leaf certificate paired with the *server*'s key.
        let mut pem = pki.leaf.to_pem().unwrap();
        pem.extend_from_slice(&pki.intermediate.to_pem().unwrap());
        let wrong_key = pki.server_key.private_key_to_pem_pkcs8().unwrap();

        // The exact message and error kind come from OpenSSL and vary between
        // versions, so only assert that building the connector fails at all
        // rather than deferring to an opaque handshake error later on.
        assert!(
            openssl_connector(TLSConfig {
                identity: Some(Identity::PKCS8 {
                    pem: &pem,
                    key: &wrong_key,
                }),
                cert_chain: None,
            })
            .is_err(),
            "a certificate that does not match its key must be rejected eagerly",
        );
    }
}
