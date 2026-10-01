//! Socket readiness and connection checks through rustix: polling, a peek at
//! the next byte on Unix, and socket errors.

use crate::{StdTcpStream, connection_in_progress, probe_connection, write_probe};
use std::io;

pub(crate) fn try_connect(stream: &mut StdTcpStream) -> io::Result<bool> {
    match has_peer(stream)? {
        Some(true) => return connected(stream),
        Some(false) => {}
        None => return probe_connection(stream),
    }
    // WSAPoll does not report failed connections before Windows 10 2004.
    if cfg!(windows)
        && let Some(error) = socket_error(stream)?
    {
        return Err(error);
    }
    use rustix::event::PollFlags;

    let events = socket_events(stream, PollFlags::OUT)?;
    if !events.intersects(PollFlags::OUT | PollFlags::ERR | PollFlags::HUP) {
        return Ok(false);
    }
    // The attempt ended, possibly after the first check, so look for a peer
    // again, then for the attempt's error.
    if has_peer(stream)? == Some(true) {
        return connected(stream);
    }
    if let Some(error) = socket_error(stream)? {
        return Err(error);
    }
    // Without either, let the write probe decide: it fails if the attempt
    // failed and its error was already retrieved, and it starts the handshake
    // of a TCP Fast Open socket that deferred it, which is writable without a
    // peer. The attempt ended, so only that handshake is still pending.
    match write_probe(stream) {
        Ok(()) => Ok(true),
        Err(err) if handshake_started(&err) || err.kind() == io::ErrorKind::WouldBlock => Ok(false),
        Err(err) => Err(err),
    }
}

/// Report a socket with a peer as connected unless its write probe fails. A
/// full send buffer can make the probe report `WouldBlock`, which still means
/// connected.
fn connected(stream: &StdTcpStream) -> io::Result<bool> {
    match write_probe(stream) {
        Err(err) if err.kind() != io::ErrorKind::WouldBlock => Err(err),
        _ => Ok(true),
    }
}

/// Whether the socket has a peer, or `None` if it cannot tell, as on WASI
/// preview 1.
fn has_peer(stream: &StdTcpStream) -> io::Result<Option<bool>> {
    match stream.peer_addr() {
        Ok(_) => Ok(Some(true)),
        // XNU reports EINVAL instead of ENOTCONN once both directions are shut.
        Err(err)
            if matches!(
                err.kind(),
                io::ErrorKind::NotConnected | io::ErrorKind::InvalidInput
            ) =>
        {
            Ok(Some(false))
        }
        Err(err) if err.kind() == io::ErrorKind::Unsupported => Ok(None),
        Err(err) => Err(err),
    }
}

/// Whether a write started the deferred handshake of a TCP Fast Open socket,
/// which reports `EINPROGRESS`.
pub(crate) fn handshake_started(err: &io::Error) -> bool {
    #[cfg(all(unix, not(target_os = "l4re")))]
    return err.raw_os_error() == Some(rustix::io::Errno::INPROGRESS.raw_os_error());
    #[cfg(not(all(unix, not(target_os = "l4re"))))]
    {
        let _ = err;
        false
    }
}

pub(crate) fn socket_events(
    stream: &StdTcpStream,
    interest: rustix::event::PollFlags,
) -> io::Result<rustix::event::PollFlags> {
    use rustix::event::{PollFd, Timespec, poll};

    let mut fds = [PollFd::new(stream, interest)];
    rustix::io::retry_on_intr(|| poll(&mut fds, Some(&Timespec::default())))?;
    let events = fds[0].revents();
    // ESP-IDF's poll API does not expose POLLNVAL.
    #[cfg(not(target_os = "espidf"))]
    if events.contains(rustix::event::PollFlags::NVAL) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid socket",
        ));
    }
    Ok(events)
}

/// Retrieve the pending socket error. WASI preview 1 does not report one.
fn socket_error(stream: &StdTcpStream) -> io::Result<Option<io::Error>> {
    match stream.take_error() {
        Err(err) if err.kind() == io::ErrorKind::Unsupported => Ok(None),
        result => result,
    }
}

/// Peek at the next byte without waiting, so that the result is what the next
/// read would return: data or EOF, `WouldBlock`, or an error once no data
/// precedes it. Like a read, the peek skips urgent data unless `SO_OOBINLINE`
/// is enabled.
#[cfg(unix)]
pub(crate) fn is_readable(stream: &StdTcpStream) -> io::Result<()> {
    use rustix::net::{RecvFlags, recv};

    rustix::io::retry_on_intr(|| {
        recv(stream, &mut [0][..], RecvFlags::PEEK | RecvFlags::DONTWAIT)
    })?;
    Ok(())
}

#[cfg(any(windows, target_os = "wasi"))]
pub(crate) fn is_readable(stream: &StdTcpStream) -> io::Result<()> {
    use rustix::event::PollFlags;

    // Winsock rejects a zero-length recv and has no MSG_DONTWAIT, so poll,
    // which preserves data and checks blocking sockets without waiting.
    // Winsock's POLLIN includes POLLRDBAND. An ordinary read cannot consume
    // that urgent data unless SO_OOBINLINE is enabled, so request normal data.
    #[cfg(windows)]
    let interest = PollFlags::RDNORM;
    #[cfg(not(windows))]
    let interest = PollFlags::IN;
    let events = socket_events(stream, interest)?;
    if events.intersects(interest | PollFlags::HUP) {
        // A read will not block. On a closed or failed socket, report its error
        // only once no data precedes it, as the next read would.
        if events.intersects(PollFlags::ERR | PollFlags::HUP)
            && rustix::io::ioctl_fionread(stream)
                .ok()
                .is_none_or(|queued| queued == 0)
            && let Some(error) = socket_error(stream)?
        {
            return Err(error);
        }
        return Ok(());
    }
    // Without a socket error, POLLERR only reports queued notifications such
    // as transmit timestamps, which a read does not consume. WSAPoll does not
    // report failed connections before Windows 10 2004, so look for a socket
    // error there too.
    if (cfg!(windows) || events.contains(PollFlags::ERR))
        && let Some(error) = socket_error(stream)?
    {
        return Err(error);
    }
    Err(io::Error::from(io::ErrorKind::WouldBlock))
}

pub(crate) fn is_writable(stream: &StdTcpStream) -> io::Result<()> {
    use rustix::event::PollFlags;

    let events = socket_events(stream, PollFlags::OUT)?;
    // WSAPoll does not report failed connections before Windows 10 2004, so
    // look for a socket error whenever the socket is not writable there.
    let check_error = events.intersects(PollFlags::ERR | PollFlags::HUP)
        || cfg!(windows) && !events.contains(PollFlags::OUT);
    if check_error && let Some(error) = socket_error(stream)? {
        return Err(error);
    }
    // Without a socket error, POLLERR only reports queued notifications such
    // as transmit timestamps. Elsewhere than on Windows, POLLHUP means that the
    // local side can no longer send; WSAPoll also reports it when only the peer
    // has stopped sending.
    if cfg!(not(windows)) && events.contains(PollFlags::HUP) {
        return Err(io::Error::from(io::ErrorKind::BrokenPipe));
    }
    // The write probe fails once the local side can no longer send: after a
    // local write shutdown, which Linux still reports as writable, or on
    // Windows after a reset whose socket error was already retrieved.
    // It reports a Fast Open handshake that it started as in progress.
    if events.intersects(PollFlags::OUT | PollFlags::HUP) {
        match write_probe(stream) {
            Err(err) if handshake_started(&err) => {
                return Err(io::Error::from(io::ErrorKind::WouldBlock));
            }
            result => result?,
        }
    } else if cfg!(windows)
        // WSAPoll may report nothing after a local write shutdown. The probe
        // fails then; on a pending connection or a full buffer, it returns
        // NotConnected or WouldBlock, or succeeds, without sending anything.
        && let Err(err) = write_probe(stream)
        && !connection_in_progress(&err)
    {
        return Err(err);
    }
    if events.contains(PollFlags::OUT) {
        Ok(())
    } else {
        Err(io::Error::from(io::ErrorKind::WouldBlock))
    }
}
