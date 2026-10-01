use super::*;
#[cfg(any(unix, windows))]
use std::net::SocketAddr;
use std::{net::TcpListener, time::Instant};

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
