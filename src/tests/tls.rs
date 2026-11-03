use super::*;

const UNTRUSTED_ROOT_CERT: &str = include_str!("../../tests/fixtures/untrusted-root.pem");

trait TestStream: Read + Write {}
impl<S: Read + Write> TestStream for S {}

fn server<T: Send + 'static>(
    serve: impl FnOnce(&mut dyn TestStream) -> io::Result<T> + Send + 'static,
) -> (SocketAddr, std::thread::JoinHandle<io::Result<T>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (socket, _) = listener.accept()?;
        socket.set_read_timeout(Some(Duration::from_secs(5)))?;
        socket.set_write_timeout(Some(Duration::from_secs(5)))?;
        cfg_if::cfg_if! {
            if #[cfg(feature = "rustls")] {
                let mut socket = socket;
                use rustls_connector::{rustls, rustls_pki_types::{PrivateKeyDer, pem::PemObject}};
                #[cfg(feature = "rustls--aws_lc_rs")]
                let provider = rustls::crypto::aws_lc_rs::default_provider();
                #[cfg(all(not(feature = "rustls--aws_lc_rs"), feature = "rustls--ring"))]
                let provider = rustls::crypto::ring::default_provider();
                let certs = certificates(CERT_CHAIN);
                let key = PrivateKeyDer::from_pem_slice(PRIVATE_KEY).unwrap();
                let config = rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(provider))
                    .with_safe_default_protocol_versions().unwrap()
                    .with_no_client_auth().with_single_cert(certs, key).unwrap();
                let mut session = rustls::ServerConnection::new(std::sync::Arc::new(config)).unwrap();
                while session.is_handshaking() {
                    session.complete_io(&mut socket)?;
                }
                let mut tls: Box<dyn TestStream> = Box::new(rustls::StreamOwned::new(session, socket));
            } else if #[cfg(feature = "openssl")] {
                let certs = openssl::x509::X509::stack_from_pem(CERT_CHAIN).unwrap();
                let key = openssl::pkey::PKey::private_key_from_pem(PRIVATE_KEY).unwrap();
                let mut builder = openssl::ssl::SslAcceptor::mozilla_intermediate(openssl::ssl::SslMethod::tls()).unwrap();
                builder.set_certificate(&certs[0]).unwrap();
                builder.set_private_key(&key).unwrap();
                for cert in &certs[1..] {
                    builder.add_extra_chain_cert(cert.clone()).unwrap();
                }
                let stream = builder.build().accept(socket)
                    .map_err(|error| io::Error::other(error.to_string()))?;
                let mut tls: Box<dyn TestStream> = Box::new(stream);
            } else {
                // PKCS#12 works on all native-tls platforms, including iOS.
                let identity = native_tls::Identity::from_pkcs12(PKCS12_IDENTITY, PKCS12_PASSWORD).unwrap();
                let acceptor = native_tls::TlsAcceptor::new(identity).unwrap();
                let stream = acceptor.accept(socket)
                    .map_err(|error| io::Error::other(error.to_string()))?;
                let mut tls: Box<dyn TestStream> = Box::new(stream);
            }
        }
        serve(tls.as_mut())
    });
    (addr, handle)
}

fn ping_pong(tls: &mut dyn TestStream) -> io::Result<()> {
    let mut request = [0; 4];
    tls.read_exact(&mut request)?;
    if &request != b"ping" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected request: {request:?}"),
        ));
    }
    tls.write_all(b"pong")?;
    tls.flush()
}

#[test]
fn nonblocking_tls_handshake_and_io() {
    let (addr, server) = server(ping_pong);
    let stream = TcpStream::connect(addr).unwrap();
    stream.set_nonblocking(true).unwrap();
    let mut upgrade = stream.into_tls(
        "localhost",
        TLSConfig {
            identity: None,
            cert_chain: Some(ROOT_CERT),
        },
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut stream = loop {
        match upgrade {
            Ok(stream) => break stream,
            Err(HandshakeError::WouldBlock(mid)) => {
                assert!(Instant::now() < deadline, "TLS handshake timed out");
                std::thread::sleep(Duration::from_millis(1));
                upgrade = mid.handshake();
            }
            Err(error) => panic!("TLS handshake failed: {error}"),
        }
    };
    assert!(!matches!(stream, TcpStream::Plain(_)));
    stream.set_nonblocking(false).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(b"ping").unwrap();
    stream.flush().unwrap();
    let mut response = [0; 4];
    stream.read_exact(&mut response).unwrap();
    assert_eq!(&response, b"pong");
    server.join().unwrap().unwrap();
}

/// Build the connector that the synchronous `into_tls` uses, so that rejection
/// tests can tell a failed handshake from a configuration error.
fn configure(config: TLSConfig<'_, '_, '_>) -> io::Result<()> {
    cfg_if::cfg_if! {
        if #[cfg(feature = "rustls")] {
            rustls_connector(config).map(drop)
        } else if #[cfg(feature = "openssl")] {
            openssl_connector(config).map(drop)
        } else {
            native_tls_connector(config).map(drop)
        }
    }
}

fn assert_verification_rejected(domain: &str, root: &str) {
    configure(TLSConfig {
        identity: None,
        cert_chain: Some(root),
    })
    .expect("the rejection must come from the handshake, not the configuration");
    let (addr, server) = server(|_| Ok(()));
    let stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let result = stream.into_tls(
        domain,
        TLSConfig {
            identity: None,
            cert_chain: Some(root),
        },
    );
    assert!(
        matches!(result, Err(HandshakeError::Failure(_))),
        "accepted an invalid server identity or did not complete its handshake: {result:?}"
    );
    // The server may receive the client's verification alert after its own
    // handshake completes, so either handshake outcome is valid on this side.
    let _ = server.join().unwrap();
}

#[test]
fn tls_rejects_wrong_hostname() {
    assert_verification_rejected("wrong.example", ROOT_CERT);
}

#[test]
fn tls_rejects_untrusted_certificate_chain() {
    assert_verification_rejected("localhost", UNTRUSTED_ROOT_CERT);
}

#[cfg(all(
    any(
        feature = "rustls-futures",
        feature = "openssl-futures",
        feature = "native-tls-futures"
    ),
    any(feature = "tokio", feature = "smol", feature = "async-global-executor"),
))]
mod asynchronous {
    use super::*;
    use async_rs::traits::{Executor, Reactor};
    use futures_io::{AsyncRead, AsyncWrite};
    use std::{future::poll_fn, pin::Pin, task::Poll};

    fn runtime() -> impl Executor + Reactor + Sync {
        cfg_if::cfg_if! {
            if #[cfg(feature = "tokio")] {
                async_rs::Runtime::tokio().unwrap()
            } else if #[cfg(feature = "smol")] {
                async_rs::Runtime::smol()
            } else {
                async_rs::Runtime::async_global_executor()
            }
        }
    }

    async fn with_timeout<T>(reactor: &impl Reactor, future: impl Future<Output = T>) -> T {
        let mut future = std::pin::pin!(future);
        let mut timeout = std::pin::pin!(reactor.sleep(Duration::from_secs(5)));
        poll_fn(|cx| {
            if let Poll::Ready(result) = future.as_mut().poll(cx) {
                return Poll::Ready(result);
            }
            assert!(
                timeout.as_mut().poll(cx).is_pending(),
                "async TLS test timed out"
            );
            Poll::Pending
        })
        .await
    }

    #[test]
    fn async_tls_handshake_and_io() {
        let runtime = runtime();
        let (addr, server) = server(ping_pong);
        runtime.block_on(with_timeout(&runtime, async {
            let stream = AsyncTcpStream::connect(&runtime, addr).await.unwrap();
            let mut stream = stream
                .into_tls(
                    "localhost",
                    TLSConfig {
                        identity: None,
                        cert_chain: Some(ROOT_CERT),
                    },
                )
                .await
                .unwrap();
            assert!(!matches!(stream, AsyncTcpStream::Plain(_)));
            let mut remaining = &b"ping"[..];
            while !remaining.is_empty() {
                let written = poll_fn(|cx| Pin::new(&mut stream).poll_write(cx, remaining))
                    .await
                    .unwrap();
                assert!(written > 0);
                remaining = &remaining[written..];
            }
            poll_fn(|cx| Pin::new(&mut stream).poll_flush(cx))
                .await
                .unwrap();
            let mut response = [0; 4];
            let mut read = 0;
            while read < response.len() {
                let n = poll_fn(|cx| Pin::new(&mut stream).poll_read(cx, &mut response[read..]))
                    .await
                    .unwrap();
                assert!(n > 0);
                read += n;
            }
            assert_eq!(&response, b"pong");
        }));
        server.join().unwrap().unwrap();
    }

    /// Build the connector that the async `into_tls` uses.
    fn configure(config: TLSConfig<'_, '_, '_>) -> io::Result<()> {
        cfg_if::cfg_if! {
            if #[cfg(feature = "rustls-futures")] {
                rustls_connector(config).map(drop)
            } else if #[cfg(feature = "openssl-futures")] {
                openssl_connector(config).map(drop)
            } else {
                native_tls_connector(config).map(drop)
            }
        }
    }

    fn assert_verification_rejected(domain: &str, root: &str) {
        configure(TLSConfig {
            identity: None,
            cert_chain: Some(root),
        })
        .expect("the rejection must come from the handshake, not the configuration");
        let runtime = runtime();
        let (addr, server) = server(|_| Ok(()));
        runtime.block_on(with_timeout(&runtime, async {
            let stream = AsyncTcpStream::connect(&runtime, addr).await.unwrap();
            assert!(
                stream
                    .into_tls(
                        domain,
                        TLSConfig {
                            identity: None,
                            cert_chain: Some(root)
                        }
                    )
                    .await
                    .is_err(),
                "accepted an invalid server identity"
            );
        }));
        let _ = server.join().unwrap();
    }

    #[test]
    fn async_tls_rejects_wrong_hostname() {
        assert_verification_rejected("wrong.example", ROOT_CERT);
    }

    #[test]
    fn async_tls_rejects_untrusted_certificate_chain() {
        assert_verification_rejected("localhost", UNTRUSTED_ROOT_CERT);
    }
}
