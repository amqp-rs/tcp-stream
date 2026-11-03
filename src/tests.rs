use super::*;
#[cfg(any(
    unix,
    windows,
    feature = "rustls",
    feature = "native-tls",
    feature = "openssl"
))]
use std::net::SocketAddr;
use std::{net::TcpListener, time::Instant};

#[cfg(any(feature = "rustls", feature = "native-tls", feature = "openssl"))]
pub(super) const ROOT_CERT: &str = include_str!("../tests/fixtures/root.pem");
#[cfg(any(feature = "rustls", feature = "openssl", feature = "native-tls"))]
pub(super) const CERT_CHAIN: &[u8] = include_bytes!("../tests/fixtures/chain.pem");
#[cfg(any(feature = "rustls", feature = "openssl", feature = "native-tls"))]
pub(super) const PRIVATE_KEY: &[u8] = include_bytes!("../tests/fixtures/key.pem");
#[cfg(any(feature = "native-tls", feature = "openssl", feature = "rustls"))]
pub(super) const PKCS12_IDENTITY: &[u8] = include_bytes!("../tests/fixtures/identity.p12");
#[cfg(any(feature = "native-tls", feature = "rustls"))]
pub(super) const PKCS12_PASSWORD: &str = "test password";
#[cfg(any(feature = "native-tls", feature = "rustls"))]
pub(super) const ENCRYPTED_KEY: &str = include_str!("../tests/fixtures/encrypted-key.pem");

/// The certificates in `pem`, read with rustls-pki-types.
#[cfg(any(feature = "rustls", feature = "openssl", feature = "native-tls"))]
pub(super) fn certificates(pem: &[u8]) -> Vec<rustls_pki_types::CertificateDer<'static>> {
    use rustls_pki_types::pem::PemObject;

    rustls_pki_types::CertificateDer::pem_slice_iter(pem)
        .collect::<Result<_, _>>()
        .unwrap()
}

/// The fixture's private key.
#[cfg(any(feature = "rustls", feature = "native-tls"))]
pub(super) fn pkcs8_key() -> rustls_pki_types::PrivatePkcs8KeyDer<'static> {
    use rustls_pki_types::pem::PemObject;

    rustls_pki_types::PrivatePkcs8KeyDer::from_pem_slice(PRIVATE_KEY).unwrap()
}

/// Check that a backend rejects a malformed PKCS#12 bundle as `InvalidData`,
/// and a password containing NUL as `InvalidInput` without exposing it.
#[cfg(any(feature = "native-tls", feature = "openssl"))]
pub(super) fn check_pkcs12_rejections<T>(build: impl Fn(TLSConfig<'_, '_, '_>) -> io::Result<T>) {
    for (der, password, expected) in [
        (&b"not a PKCS12 bundle"[..], "", io::ErrorKind::InvalidData),
        (
            PKCS12_IDENTITY,
            "secret\0password",
            io::ErrorKind::InvalidInput,
        ),
    ] {
        let error = build(TLSConfig {
            identity: Some(Identity::PKCS12 { der, password }),
            cert_chain: None,
        })
        .map(drop)
        .expect_err("accepted an invalid PKCS#12 identity");
        assert_eq!(error.kind(), expected);
        assert!(!format!("{error:?}").contains("secret"));
    }
}

/// Poll `future` once, with a waker that does nothing.
#[cfg(any(feature = "native-tls-futures", feature = "openssl-futures"))]
pub(super) fn poll_once<F: Future>(future: F) -> std::task::Poll<F::Output> {
    std::pin::pin!(future).poll(&mut std::task::Context::from_waker(std::task::Waker::noop()))
}

#[cfg(any(feature = "native-tls", feature = "openssl"))]
pub(super) fn password_prompt_test_child(test_name: &str) -> bool {
    use std::process::{Command, Stdio};

    const CHILD_ENV: &str = "TCP_STREAM_PASSWORD_PROMPT_TEST_CHILD";
    if std::env::var(CHILD_ENV).is_ok_and(|name| name == test_name) {
        return true;
    }

    // OpenSSL can open /dev/tty even with null stdin. Bound the subprocess so
    // restoring an interactive callback cannot hang the test runner.
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test_name, "--nocapture"])
        .env(CHILD_ENV, test_name)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Drain the pipes while waiting, so a verbose child cannot block on them.
    let drain = |mut pipe: Box<dyn Read + Send>| {
        std::thread::spawn(move || {
            let mut output = Vec::new();
            pipe.read_to_end(&mut output).map(|_| output)
        })
    };
    let stdout = drain(Box::new(child.stdout.take().unwrap()));
    let stderr = drain(Box::new(child.stderr.take().unwrap()));
    let deadline = Instant::now() + Duration::from_secs(5);
    let (status, timed_out) = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break (status, false);
        }
        if Instant::now() >= deadline {
            // It may have exited since try_wait; always reap it below.
            let _ = child.kill();
            break (child.wait().unwrap(), true);
        }
        std::thread::sleep(Duration::from_millis(1));
    };
    let stdout = stdout.join().unwrap().unwrap();
    let stderr = stderr.join().unwrap().unwrap();
    let stderr = String::from_utf8_lossy(&stderr);
    assert!(
        !timed_out,
        "{test_name} did not finish within five seconds, possibly waiting for a password:\n{}\n{stderr}",
        String::from_utf8_lossy(&stdout)
    );
    assert!(status.success(), "{test_name} child failed: {stderr}");
    assert!(
        String::from_utf8_lossy(&stdout).contains("1 passed"),
        "{test_name} child did not run the regression"
    );
    let stderr = stderr.to_ascii_lowercase();
    assert!(
        !stderr.contains("pass phrase") && !stderr.contains("passphrase"),
        "{test_name} requested a password: {stderr}"
    );
    false
}

#[cfg(any(feature = "rustls", feature = "native-tls", feature = "openssl"))]
pub(super) fn check_custom_roots<T>(
    build: impl for<'chain> Fn(TLSConfig<'static, 'static, 'chain>) -> io::Result<T>,
) {
    let malformed_certs = [
        "-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n",
        "-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n",
        "-----BEGIN CERTIFICATE-----\nAQID\n",
    ];
    // A chain without certificates adds no roots.
    for empty in ["", "no certificates here"] {
        if let Err(error) = build(TLSConfig {
            identity: None,
            cert_chain: Some(empty),
        }) {
            panic!("rejected custom roots without certificates {empty:?}: {error}");
        }
    }
    let mut inputs = Vec::new();
    for malformed in malformed_certs {
        inputs.push(malformed.into());
        inputs.push(format!("{ROOT_CERT}{malformed}"));
        inputs.push(format!("{malformed}{ROOT_CERT}"));
    }
    for input in inputs {
        let error = build(TLSConfig {
            identity: None,
            cert_chain: Some(&input),
        })
        .err()
        .unwrap_or_else(|| panic!("accepted invalid custom roots: {input:?}"));
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
}

fn socket_pair() -> (TcpStream, StdTcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (peer, _) = listener.accept().unwrap();
    (stream, peer)
}

/// Check `done` every millisecond until it returns true, failing with `what`
/// after `timeout`.
fn wait_until(timeout: Duration, what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + timeout;
    while !done() {
        assert!(Instant::now() < deadline, "{what}");
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn wait_readable(stream: &TcpStream) {
    wait_until(
        Duration::from_secs(2),
        "socket never became readable",
        || match stream.is_readable() {
            Ok(()) => true,
            Err(error) => {
                assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
                false
            }
        },
    );
}

/// Wait until polling `stream` reports one of `events`, without consuming data.
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
fn wait_for_events(stream: &StdTcpStream, events: rustix::event::PollFlags) {
    use crate::rustix_checks::socket_events;

    wait_until(
        Duration::from_secs(2),
        &format!("{events:?} never reported"),
        || socket_events(stream, events).unwrap().intersects(events),
    );
}

/// Send one byte of urgent data from `peer`.
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
fn send_urgent_byte(peer: &StdTcpStream) {
    assert_eq!(
        socket2::SockRef::from(peer).send_out_of_band(b"!").unwrap(),
        1
    );
}

#[test]
fn identity_debug_redacts_secrets_in_owned_and_borrowed_configs() {
    for (identity, expected) in [
        (
            OwnedIdentity::PKCS12 {
                der: b"secret bundle".to_vec(),
                password: "secret password".into(),
            },
            "PKCS12 { .. }",
        ),
        (
            OwnedIdentity::PKCS8 {
                pem: b"certificate".to_vec(),
                key: b"secret key".to_vec(),
            },
            "PKCS8 { .. }",
        ),
    ] {
        assert_eq!(format!("{identity:?}"), expected);
        assert_eq!(format!("{:?}", identity.as_ref()), expected);
        let config = OwnedTLSConfig {
            identity: Some(identity),
            cert_chain: None,
        };
        for output in [format!("{config:?}"), format!("{:?}", config.as_ref())] {
            assert!(output.contains(expected));
            assert!(!output.contains("secret"));
            assert!(!output.contains("115, 101, 99, 114, 101, 116"));
        }
    }
}

#[test]
fn writable_check_does_not_send_data() {
    let (stream, mut peer) = socket_pair();
    peer.set_nonblocking(true).unwrap();
    stream.is_writable().unwrap();
    assert_eq!(
        peer.read(&mut [0]).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
}

#[test]
fn readable_check_reports_no_data() {
    let (stream, _peer) = socket_pair();
    stream.set_nonblocking(true).unwrap();
    assert_eq!(
        stream.is_readable().unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
}

#[test]
fn readable_check_does_not_wait_on_a_blocking_socket() {
    let (stream, peer) = socket_pair();
    let (send, receive) = std::sync::mpsc::channel();
    let check = std::thread::spawn(move || send.send(stream.is_readable()).unwrap());
    let result = receive.recv_timeout(Duration::from_secs(2));
    // Unblock the check, if it wrongly blocks, before joining its thread.
    drop(peer);
    check.join().unwrap();
    assert_eq!(
        result.expect("readiness check blocked").unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
}

#[test]
fn readable_check_preserves_data_and_reports_eof() {
    let (mut stream, mut peer) = socket_pair();
    stream.set_nonblocking(true).unwrap();
    peer.write_all(b"ping").unwrap();
    wait_readable(&stream);
    // Repeating a readiness check must leave all application bytes available.
    stream.is_readable().unwrap();
    // A TCP message may arrive across several reads.
    stream.set_nonblocking(false).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut bytes = [0; 4];
    stream.read_exact(&mut bytes).unwrap();
    assert_eq!(&bytes, b"ping");
    stream.set_nonblocking(true).unwrap();
    assert_eq!(
        stream.is_readable().unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    peer.shutdown(std::net::Shutdown::Write).unwrap();
    wait_readable(&stream);
    assert_eq!(stream.read(&mut [0]).unwrap(), 0);
}

#[cfg(any(unix, windows))]
#[test]
fn readable_check_reports_a_reset_connection() {
    let (stream, peer) = socket_pair();
    stream.set_nonblocking(true).unwrap();
    // Closing with a zero linger time resets the connection.
    socket2::SockRef::from(&peer)
        .set_linger(Some(Duration::ZERO))
        .unwrap();
    drop(peer);
    wait_until(
        Duration::from_secs(2),
        "reset was never reported",
        || match stream.is_readable() {
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => false,
            Err(error) => {
                assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
                true
            }
            // Winsock may keep the reset for the next read instead.
            Ok(()) if cfg!(windows) => {
                assert_eq!(
                    (&*stream).read(&mut [0]).unwrap_err().kind(),
                    io::ErrorKind::ConnectionReset
                );
                true
            }
            Ok(()) => panic!("reset connection reported as readable"),
        },
    );
}

// Other platforms may discard received data on a reset.
#[cfg(target_os = "linux")]
#[test]
fn readable_check_reports_data_received_before_a_reset() {
    // Also with an urgent byte, delivered separately, ahead of the data.
    for urgent in [false, true] {
        let (mut stream, mut peer) = socket_pair();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        if urgent {
            socket2::SockRef::from(&*stream)
                .set_out_of_band_inline(false)
                .unwrap();
            send_urgent_byte(&peer);
        }
        peer.write_all(b"ping").unwrap();
        wait_readable(&stream);
        socket2::SockRef::from(&peer)
            .set_linger(Some(Duration::ZERO))
            .unwrap();
        drop(peer);
        wait_for_events(&stream, rustix::event::PollFlags::ERR);
        stream.is_readable().unwrap();
        let mut bytes = [0; 4];
        stream.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"ping");
        assert_eq!(
            stream.read(&mut [0]).unwrap_err().kind(),
            io::ErrorKind::ConnectionReset,
            "urgent: {urgent}"
        );
    }
}

// Linux keeps the EOF for the next read when a reset follows the peer's FIN.
#[cfg(target_os = "linux")]
#[test]
fn readable_check_reports_eof_before_a_later_reset() {
    let (mut stream, peer) = socket_pair();
    drop(peer);
    wait_readable(&stream);
    // The closed peer answers with a reset.
    stream.write_all(b"ping").unwrap();
    wait_for_events(&stream, rustix::event::PollFlags::ERR);
    stream.is_readable().unwrap();
    assert_eq!(stream.read(&mut [0]).unwrap(), 0);
    // The check left the reset for the socket's next error report.
    assert_eq!(
        stream.take_error().unwrap().unwrap().kind(),
        io::ErrorKind::BrokenPipe
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn readable_check_reports_an_unconnected_socket() {
    let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
    let stream = TcpStream::Plain(socket.into());
    assert_eq!(
        stream.is_readable().unwrap_err().kind(),
        io::ErrorKind::NotConnected
    );
}

#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
#[test]
fn urgent_data_without_inline_delivery_is_not_readable() {
    use rustix::event::PollFlags;

    let (mut stream, peer) = socket_pair();
    stream.set_nonblocking(true).unwrap();
    socket2::SockRef::from(&*stream)
        .set_out_of_band_inline(false)
        .unwrap();
    send_urgent_byte(&peer);
    #[cfg(windows)]
    let interest = PollFlags::RDBAND;
    #[cfg(not(windows))]
    let interest = PollFlags::PRI;
    // Wait for the urgent data. On Windows POLLIN includes this event even
    // though the ordinary read below would still block.
    wait_for_events(&stream, interest);
    assert_eq!(
        stream.is_readable().unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    assert_eq!(
        stream.read(&mut [0]).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
}

#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
#[test]
fn urgent_data_with_inline_delivery_is_readable() {
    let (mut stream, peer) = socket_pair();
    socket2::SockRef::from(&*stream)
        .set_out_of_band_inline(true)
        .unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    send_urgent_byte(&peer);
    wait_readable(&stream);
    let mut byte = [0];
    stream.read_exact(&mut byte).unwrap();
    assert_eq!(&byte, b"!");
}

#[cfg(any(unix, windows))]
#[test]
fn full_send_buffer_is_not_writable_but_is_connected() {
    let (mut stream, peer) = socket_pair();
    socket2::SockRef::from(&*stream)
        .set_send_buffer_size(4096)
        .unwrap();
    socket2::SockRef::from(&peer)
        .set_recv_buffer_size(4096)
        .unwrap();
    stream.set_nonblocking(true).unwrap();
    let data = [0; 65536];
    wait_until(
        Duration::from_secs(2),
        "send buffer never became non-writable",
        || match stream.write(&data) {
            Ok(_) => false,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => match stream.is_writable() {
                Ok(()) => false,
                Err(error) => {
                    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
                    true
                }
            },
            Err(error) => panic!("write failed: {error}"),
        },
    );
    assert!(stream.try_connect().unwrap());
}

#[test]
fn writable_check_reports_a_local_write_shutdown() {
    let (stream, _peer) = socket_pair();
    stream.shutdown(std::net::Shutdown::Write).unwrap();
    assert_eq!(
        stream.is_writable().unwrap_err().kind(),
        io::ErrorKind::BrokenPipe
    );
}

#[cfg(windows)]
#[test]
fn local_write_shutdown_errors_are_broken_pipes() {
    let error = shutdown_as_broken_pipe(io::Error::from_raw_os_error(
        rustix::io::Errno::SHUTDOWN.raw_os_error(),
    ));
    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    let error = shutdown_as_broken_pipe(io::Error::from(io::ErrorKind::WouldBlock));
    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
}

#[test]
fn connection_check_reports_a_local_write_shutdown() {
    let (mut stream, _peer) = socket_pair();
    stream.shutdown(std::net::Shutdown::Write).unwrap();
    assert_eq!(
        stream.try_connect().unwrap_err().kind(),
        io::ErrorKind::BrokenPipe
    );
}

#[test]
fn peer_send_shutdown_does_not_prevent_writing() {
    let (mut stream, mut peer) = socket_pair();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    peer.shutdown(std::net::Shutdown::Write).unwrap();
    assert_eq!(stream.read(&mut [0]).unwrap(), 0);
    stream.is_writable().unwrap();
    stream.write_all(b"ping").unwrap();
    let mut data = [0; 4];
    peer.read_exact(&mut data).unwrap();
    assert_eq!(&data, b"ping");
}

/// Start a nonblocking connection to a port without a listener, or return
/// `None` if the refusal is reported immediately, as it can be on macOS, where
/// the tests using it then check nothing. Keep the returned socket while the
/// stream is in use: it reserves the port.
#[cfg(any(unix, windows))]
fn refused_connection() -> Option<(TcpStream, socket2::Socket)> {
    // Reserve the port without listening so another test cannot reuse it.
    let unavailable = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )
    .unwrap();
    unavailable
        .bind(&"127.0.0.1:0".parse::<SocketAddr>().unwrap().into())
        .unwrap();
    let addr = unavailable.local_addr().unwrap();
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )
    .unwrap();
    socket.set_nonblocking(true).unwrap();
    // An immediate refusal has already reported the error; only pending
    // connections need to retrieve it later through the wrapped socket.
    if socket
        .connect(&addr)
        .is_err_and(|error| error.kind() == io::ErrorKind::ConnectionRefused)
    {
        return None;
    }
    Some((TcpStream::Plain(socket.into()), unavailable))
}

/// Windows retries a refused loopback connection for about two seconds.
#[cfg(any(unix, windows))]
const REFUSAL_DEADLINE: Duration = Duration::from_secs(10);

#[cfg(any(unix, windows))]
#[test]
fn failed_nonblocking_connection_reports_the_socket_error() {
    let Some((mut stream, _reservation)) = refused_connection() else {
        return;
    };
    wait_until(
        REFUSAL_DEADLINE,
        "connection failure was not reported",
        || match stream.try_connect() {
            Err(error) => {
                assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
                true
            }
            Ok(false) => false,
            Ok(true) => panic!("connection to closed listener succeeded"),
        },
    );
}

#[cfg(any(unix, windows))]
#[test]
fn failed_connection_stays_failed_after_its_error_is_retrieved() {
    let Some((mut stream, _reservation)) = refused_connection() else {
        return;
    };
    wait_until(
        REFUSAL_DEADLINE,
        "connection failure was not reported",
        || match stream.is_writable() {
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => false,
            Err(error) => {
                assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
                true
            }
            Ok(()) => panic!("connection to closed listener became writable"),
        },
    );
    assert!(stream.try_connect().is_err());
}

#[cfg(feature = "native-tls")]
#[test]
fn native_tls_rejects_nul_in_domain_without_panicking() {
    let connector = NativeTlsConnector::new().unwrap();
    let (stream, _peer) = socket_pair();
    let result = stream.into_native_tls(&connector, "localhost\0.invalid");
    assert!(
        matches!(result, Err(HandshakeError::Failure(error)) if error.kind() == io::ErrorKind::InvalidInput)
    );
}

#[cfg(feature = "openssl")]
#[test]
fn openssl_rejects_nul_in_domain_without_panicking() {
    let connector = openssl_connector(TLSConfig::default()).unwrap();
    let (stream, _peer) = socket_pair();
    let result = stream.into_openssl(&connector, "localhost\0.invalid");
    assert!(
        matches!(result, Err(HandshakeError::Failure(error)) if error.kind() == io::ErrorKind::InvalidInput)
    );
}

#[cfg(any(feature = "native-tls-futures", feature = "openssl-futures"))]
mod asynchronous {
    use super::*;
    use futures_io::{AsyncRead, AsyncWrite};
    use std::{
        pin::Pin,
        task::{Context, Poll},
    };

    struct NoDebug;

    impl AsyncRead for NoDebug {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(0))
        }
    }

    impl AsyncWrite for NoDebug {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(data.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[cfg(feature = "native-tls-futures")]
    #[test]
    fn native_tls_rejects_nul_in_domain_before_async_io() {
        let result = poll_once(
            AsyncTcpStream::Plain(NoDebug)
                .into_native_tls(NativeTlsConnector::builder(), "localhost\0.invalid"),
        );
        assert!(
            matches!(result, Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::InvalidInput)
        );
    }

    #[cfg(feature = "openssl-futures")]
    #[test]
    fn openssl_rejects_nul_in_domain_before_async_io() {
        let connector = openssl_connector(TLSConfig::default()).unwrap();
        let result = poll_once(
            AsyncTcpStream::Plain(NoDebug).into_openssl(&connector, "localhost\0.invalid"),
        );
        assert!(
            matches!(result, Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::InvalidInput)
        );
    }
}

#[cfg(any(
    all(
        feature = "rustls",
        any(feature = "rustls--aws_lc_rs", feature = "rustls--ring")
    ),
    all(
        not(feature = "rustls"),
        any(feature = "openssl", feature = "native-tls")
    ),
))]
mod tls;
