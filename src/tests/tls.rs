use super::*;

const UNTRUSTED_ROOT_CERT: &str = include_str!("../../tests/fixtures/untrusted-root.pem");

/// The roots that the client trusts to reach the test server. A Schannel server
/// only sends the intermediates found in the system stores, so the Windows
/// Native TLS server sends its leaf alone: trust the intermediate as well there.
fn trusted_roots() -> &'static str {
    cfg_if::cfg_if! {
        if #[cfg(all(windows, not(feature = "rustls"), not(feature = "openssl")))] {
            static ROOTS: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
                let chain = std::str::from_utf8(CERT_CHAIN).unwrap();
                let begin = "-----BEGIN CERTIFICATE-----";
                let intermediate = chain[begin.len()..].find(begin).unwrap() + begin.len();
                chain[intermediate..].to_owned()
            });
            &ROOTS
        } else {
            ROOT_CERT
        }
    }
}

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
            cert_chain: Some(trusted_roots()),
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
    assert_verification_rejected("wrong.example", trusted_roots());
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
                        cert_chain: Some(trusted_roots()),
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
        assert_verification_rejected("wrong.example", trusted_roots());
    }

    #[test]
    fn async_tls_rejects_untrusted_certificate_chain() {
        assert_verification_rejected("localhost", UNTRUSTED_ROOT_CERT);
    }

    // async-openssl buffers OpenSSL's output: bytes that a write accepted are
    // sent before later writes, and a cancelled write never replaces them.
    #[cfg(feature = "openssl-futures")]
    mod buffered_writes {
        use super::*;
        use std::{
            sync::{
                Arc, Mutex,
                atomic::{AtomicUsize, Ordering},
                mpsc,
            },
            task::{Context, Wake, Waker},
        };

        #[derive(Default)]
        struct WriteGate {
            blocked: bool,
            waker: Option<Waker>,
            max_write: Option<usize>,
            read_blocked: bool,
            read_waker: Option<Waker>,
        }

        struct Gated<S> {
            inner: S,
            gate: Arc<Mutex<WriteGate>>,
        }

        impl<S: AsyncRead + Unpin> AsyncRead for Gated<S> {
            fn poll_read(
                self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &mut [u8],
            ) -> Poll<io::Result<usize>> {
                let this = self.get_mut();
                let mut gate = this.gate.lock().unwrap();
                if gate.read_blocked {
                    // Used only after handshaking to make the pending-reader
                    // ordering independent of incoming TLS session tickets.
                    gate.read_waker = Some(cx.waker().clone());
                    return Poll::Pending;
                }
                drop(gate);
                Pin::new(&mut this.inner).poll_read(cx, buf)
            }
        }

        impl<S: AsyncWrite + Unpin> AsyncWrite for Gated<S> {
            fn poll_write(
                self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<io::Result<usize>> {
                let this = self.get_mut();
                let mut gate = this.gate.lock().unwrap();
                if gate.blocked {
                    gate.waker = Some(cx.waker().clone());
                    return Poll::Pending;
                }
                let count = gate.max_write.unwrap_or(buf.len()).min(buf.len());
                drop(gate);
                Pin::new(&mut this.inner).poll_write(cx, &buf[..count])
            }

            fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Pin::new(&mut self.get_mut().inner).poll_flush(cx)
            }

            fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Pin::new(&mut self.get_mut().inner).poll_close(cx)
            }
        }

        fn release(gate: &Mutex<WriteGate>) {
            let waker = {
                let mut gate = gate.lock().unwrap();
                gate.blocked = false;
                gate.waker.take()
            };
            if let Some(waker) = waker {
                waker.wake();
            }
        }

        fn release_reads(gate: &Mutex<WriteGate>) {
            let waker = {
                let mut gate = gate.lock().unwrap();
                gate.read_blocked = false;
                gate.read_waker.take()
            };
            if let Some(waker) = waker {
                waker.wake();
            }
        }

        /// Connect through `into_openssl`, or wrap a stream that the caller
        /// built and handshook itself when `preconfigured` is set.
        async fn connect<R: Reactor + Sync>(
            reactor: &R,
            addr: SocketAddr,
            gate: Arc<Mutex<WriteGate>>,
            preconfigured: bool,
        ) -> AsyncTcpStream<Gated<R::TcpStream>> {
            let transport = Gated {
                inner: reactor.tcp_connect(addr).await.unwrap(),
                gate,
            };
            let connector = openssl_connector(TLSConfig {
                identity: None,
                cert_chain: Some(ROOT_CERT),
            })
            .unwrap();
            if preconfigured {
                let mut tls: OpensslAsyncStream<_> = async_openssl::SslStream::new(
                    connector
                        .configure()
                        .unwrap()
                        .into_ssl("localhost")
                        .unwrap(),
                    transport,
                )
                .unwrap();
                Pin::new(&mut tls).connect().await.unwrap();
                AsyncTcpStream::Openssl(tls)
            } else {
                AsyncTcpStream::Plain(transport)
                    .into_openssl(&connector, "localhost")
                    .await
                    .unwrap()
            }
        }

        async fn write_all<W: AsyncWrite + Unpin>(stream: &mut W, mut remaining: &[u8]) {
            while !remaining.is_empty() {
                let written = poll_fn(|cx| Pin::new(&mut *stream).poll_write(cx, remaining))
                    .await
                    .unwrap();
                assert!(written > 0);
                remaining = &remaining[written..];
            }
        }

        #[test]
        fn cancelled_write_does_not_replace_the_next_write() {
            cancelled_write(false);
        }

        #[test]
        fn preconfigured_streams_handle_cancelled_writes() {
            cancelled_write(true);
        }

        fn cancelled_write(preconfigured: bool) {
            let (size, receive_size) = mpsc::channel();
            let (addr, server) = server(move |tls| {
                let size = receive_size.recv_timeout(Duration::from_secs(5)).unwrap();
                let mut bytes = vec![0; size];
                tls.read_exact(&mut bytes)?;
                tls.write_all(b"ok")?;
                tls.flush()?;
                Ok(bytes)
            });
            let runtime = runtime();
            let expected = runtime.block_on(with_timeout(&runtime, async {
                let gate = Arc::new(Mutex::new(WriteGate::default()));
                let mut stream = connect(&runtime, addr, gate.clone(), preconfigured).await;

                gate.lock().unwrap().blocked = true;
                let old = Vec::from(&b"lost"[..]);
                let attempt =
                    poll_fn(|cx| Poll::Ready(Pin::new(&mut stream).poll_write(cx, &old))).await;
                let accepted = match attempt {
                    Poll::Pending => 0,
                    Poll::Ready(result) => result.unwrap(),
                };
                assert!(accepted <= old.len());
                // A buffering adapter is allowed to accept bytes immediately.
                // Only that reported prefix may precede the replacement write.
                let mut expected = old[..accepted].to_vec();
                let new = Vec::from(&b"ping"[..]);
                expected.extend_from_slice(&new);
                size.send(expected.len()).unwrap();
                release(&gate);
                write_all(&mut stream, &new).await;
                poll_fn(|cx| Pin::new(&mut stream).poll_flush(cx))
                    .await
                    .unwrap();
                read_ack(&mut stream).await;
                expected
            }));
            assert_eq!(server.join().unwrap().unwrap(), expected);
        }

        #[test]
        fn pending_write_accepts_none_of_its_cancelled_input() {
            let expected = b"keptreplacement";
            let (addr, server) = server(|tls| {
                let mut bytes = vec![0; 15];
                tls.read_exact(&mut bytes)?;
                tls.write_all(b"ok")?;
                tls.flush()?;
                Ok(bytes)
            });
            let runtime = runtime();
            runtime.block_on(with_timeout(&runtime, async {
                let gate = Arc::new(Mutex::new(WriteGate::default()));
                let mut stream = connect(&runtime, addr, gate.clone(), false).await;
                gate.lock().unwrap().blocked = true;
                // The first write is accepted into owned storage.
                write_all(&mut stream, b"kept").await;
                let cancelled = Vec::from(&b"drop"[..]);
                assert!(
                    poll_fn(|cx| Poll::Ready(Pin::new(&mut stream).poll_write(cx, &cancelled)))
                        .await
                        .is_pending()
                );
                drop(cancelled);
                release(&gate);
                // A different length also catches OpenSSL's BAD_WRITE_RETRY.
                write_all(&mut stream, b"replacement").await;
                poll_fn(|cx| Pin::new(&mut stream).poll_flush(cx))
                    .await
                    .unwrap();
                read_ack(&mut stream).await;
            }));
            assert_eq!(server.join().unwrap().unwrap(), expected);
        }

        #[derive(Clone, Copy)]
        enum Finish {
            Read,
            Flush,
            Close,
        }

        #[test]
        fn accepted_writes_are_sent_by_read_flush_and_close() {
            let runtime = runtime();
            for finish in [Finish::Read, Finish::Flush, Finish::Close] {
                let (addr, server) = server(move |tls| {
                    let mut bytes = [0; 4];
                    tls.read_exact(&mut bytes)?;
                    match finish {
                        Finish::Read => {
                            tls.write_all(b"pong")?;
                            tls.flush()?;
                        }
                        Finish::Close => {
                            if tls.read(&mut [0])? != 0 {
                                return Err(io::Error::other("data followed the last write"));
                            }
                        }
                        Finish::Flush => {}
                    }
                    Ok(bytes)
                });
                runtime.block_on(with_timeout(&runtime, async {
                    let gate = Arc::new(Mutex::new(WriteGate::default()));
                    let mut stream = connect(&runtime, addr, gate.clone(), false).await;
                    gate.lock().unwrap().blocked = true;
                    write_all(&mut stream, b"ping").await;
                    // Empty writes and reads must complete even with queued data.
                    assert_eq!(
                        poll_fn(|cx| Pin::new(&mut stream).poll_write(cx, &[]))
                            .await
                            .unwrap(),
                        0
                    );
                    assert_eq!(
                        poll_fn(|cx| Pin::new(&mut stream).poll_read(cx, &mut []))
                            .await
                            .unwrap(),
                        0
                    );
                    let mut response = [0; 4];
                    let pending = poll_fn(|cx| {
                        Poll::Ready(match finish {
                            Finish::Read => Pin::new(&mut stream)
                                .poll_read(cx, &mut response)
                                .map_ok(|_| ()),
                            Finish::Flush => Pin::new(&mut stream).poll_flush(cx),
                            Finish::Close => Pin::new(&mut stream).poll_close(cx),
                        })
                    })
                    .await;
                    assert!(pending.is_pending());
                    release(&gate);
                    match finish {
                        Finish::Read => {
                            let mut read = 0;
                            while read < response.len() {
                                let count = poll_fn(|cx| {
                                    Pin::new(&mut stream).poll_read(cx, &mut response[read..])
                                })
                                .await
                                .unwrap();
                                assert!(count > 0);
                                read += count;
                            }
                            assert_eq!(&response, b"pong");
                        }
                        Finish::Flush => poll_fn(|cx| Pin::new(&mut stream).poll_flush(cx))
                            .await
                            .unwrap(),
                        Finish::Close => poll_fn(|cx| Pin::new(&mut stream).poll_close(cx))
                            .await
                            .unwrap(),
                    }
                }));
                assert_eq!(&server.join().unwrap().unwrap(), b"ping");
            }
        }

        #[test]
        fn vectored_writes_preserve_large_input_with_partial_transport_writes() {
            let input: Vec<_> = (0..(32 * 1024 + 43)).map(|n| (n % 251) as u8).collect();
            let size = input.len();
            let (addr, server) = server(move |tls| {
                let mut bytes = vec![0; size];
                tls.read_exact(&mut bytes)?;
                tls.write_all(b"ok")?;
                tls.flush()?;
                Ok(bytes)
            });
            let runtime = runtime();
            runtime.block_on(with_timeout(&runtime, async {
                let gate = Arc::new(Mutex::new(WriteGate::default()));
                let mut stream = connect(&runtime, addr, gate.clone(), true).await;
                {
                    let mut gate = gate.lock().unwrap();
                    gate.max_write = Some(97);
                    gate.blocked = true;
                }
                let bufs = [IoSlice::new(&[]), IoSlice::new(&input)];
                let count = poll_fn(|cx| Pin::new(&mut stream).poll_write_vectored(cx, &bufs))
                    .await
                    .unwrap();
                assert!(
                    count > 0 && count <= 16 * 1024,
                    "write buffering is unbounded"
                );
                release(&gate);
                write_all(&mut stream, &input[count..]).await;
                poll_fn(|cx| Pin::new(&mut stream).poll_flush(cx))
                    .await
                    .unwrap();
                // Wait for the peer to consume the payload, and read any TLS
                // session tickets before dropping the client socket. Otherwise
                // unread server data can make TCP reset the connection while
                // the peer is still processing the final records.
                read_ack(&mut stream).await;
            }));
            assert_eq!(server.join().unwrap().unwrap(), input);
        }

        async fn read_ack<R: AsyncRead + Unpin>(stream: &mut R) {
            let mut ack = [0; 2];
            let mut read = 0;
            while read < ack.len() {
                let count = poll_fn(|cx| Pin::new(&mut *stream).poll_read(cx, &mut ack[read..]))
                    .await
                    .unwrap();
                assert!(count > 0);
                read += count;
            }
            assert_eq!(&ack, b"ok");
        }

        #[derive(Default)]
        struct WakeCount(AtomicUsize);

        impl Wake for WakeCount {
            fn wake(self: Arc<Self>) {
                self.wake_by_ref();
            }

            fn wake_by_ref(self: &Arc<Self>) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }

        #[test]
        fn reader_and_writer_keep_their_wakeups_while_draining() {
            let runtime = runtime();
            for preconfigured in [false, true] {
                for writer_first in [false, true] {
                    drain_wakeups(&runtime, preconfigured, writer_first);
                }
            }
        }

        #[test]
        fn reader_waiting_before_a_write_is_woken_to_send_it() {
            let runtime = runtime();
            for preconfigured in [false, true] {
                let (addr, server) = server(|tls| {
                    let mut bytes = [0; 4];
                    tls.read_exact(&mut bytes)?;
                    tls.write_all(b"ok")?;
                    tls.flush()?;
                    Ok(bytes)
                });
                runtime.block_on(with_timeout(&runtime, async {
                    let gate = Arc::new(Mutex::new(WriteGate::default()));
                    let mut stream = connect(&runtime, addr, gate.clone(), preconfigured).await;
                    gate.lock().unwrap().read_blocked = true;
                    let reader = Arc::new(WakeCount::default());
                    let writer = Arc::new(WakeCount::default());
                    let reader_waker = Waker::from(reader.clone());
                    let writer_waker = Waker::from(writer.clone());
                    let mut reader_cx = Context::from_waker(&reader_waker);
                    let mut writer_cx = Context::from_waker(&writer_waker);
                    let mut response = [0; 1];
                    assert!(
                        Pin::new(&mut stream)
                            .poll_read(&mut reader_cx, &mut response)
                            .is_pending()
                    );
                    gate.lock().unwrap().blocked = true;
                    assert!(matches!(
                        Pin::new(&mut stream).poll_write(&mut writer_cx, b"ping"),
                        Poll::Ready(Ok(4))
                    ));
                    assert!(
                        Pin::new(&mut stream)
                            .poll_read(&mut reader_cx, &mut response)
                            .is_pending()
                    );
                    let before = reader.0.load(Ordering::Relaxed);
                    release(&gate);
                    assert!(
                        reader.0.load(Ordering::Relaxed) > before,
                        "transport writability did not wake its reader"
                    );
                    release_reads(&gate);
                    // No flush or further write drives this exchange: the
                    // reader must send the request before a reply exists.
                    read_ack(&mut stream).await;
                }));
                assert_eq!(&server.join().unwrap().unwrap(), b"ping");
            }
        }

        fn drain_wakeups(
            runtime: &(impl Executor + Reactor + Sync),
            preconfigured: bool,
            writer_first: bool,
        ) {
            let (addr, server) = server(|tls| {
                // The peer waits for both writes before replying, so a reader
                // that sends the first write cannot make the writer progress
                // by receiving peer input. The stream has to wake the writer.
                let mut bytes = [0; 8];
                tls.read_exact(&mut bytes)?;
                tls.write_all(b"ok")?;
                tls.flush()?;
                Ok(bytes)
            });
            runtime.block_on(with_timeout(runtime, async {
                let gate = Arc::new(Mutex::new(WriteGate::default()));
                let mut stream = connect(runtime, addr, gate.clone(), preconfigured).await;
                gate.lock().unwrap().blocked = true;
                write_all(&mut stream, b"kept").await;
                let writer = Arc::new(WakeCount::default());
                let reader = Arc::new(WakeCount::default());
                let writer_waker = Waker::from(writer.clone());
                let reader_waker = Waker::from(reader.clone());
                let mut writer_cx = Context::from_waker(&writer_waker);
                let mut reader_cx = Context::from_waker(&reader_waker);
                let mut response = [0; 1];
                for writing in [writer_first, !writer_first] {
                    if writing {
                        assert!(
                            Pin::new(&mut stream)
                                .poll_write(&mut writer_cx, b"next")
                                .is_pending()
                        );
                    } else {
                        assert!(
                            Pin::new(&mut stream)
                                .poll_read(&mut reader_cx, &mut response)
                                .is_pending()
                        );
                    }
                }
                release(&gate);
                // Even if the last-polled half is cancelled here, transport
                // readiness must wake the half that remains interested.
                assert!(
                    writer.0.load(Ordering::Relaxed) > 0,
                    "writer lost its wakeup"
                );
                assert!(
                    reader.0.load(Ordering::Relaxed) > 0,
                    "reader lost its wakeup"
                );
                if writer_first {
                    assert!(
                        Pin::new(&mut stream)
                            .poll_read(&mut reader_cx, &mut response)
                            .is_pending()
                    );
                }
                write_all(&mut stream, b"next").await;
                poll_fn(|cx| Pin::new(&mut stream).poll_flush(cx))
                    .await
                    .unwrap();
                read_ack(&mut stream).await;
            }));
            assert_eq!(&server.join().unwrap().unwrap(), b"keptnext");
        }
    }
}
