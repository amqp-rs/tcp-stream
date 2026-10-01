//! Socket readiness and connection checks with zero-length read and write
//! probes, for targets without rustix support.

use crate::{StdTcpStream, probe_connection, write_probe};
use std::io::{self, Read};

/// Without rustix, a deferred TCP Fast Open handshake is not recognized.
pub(crate) fn handshake_started(_: &io::Error) -> bool {
    false
}

pub(crate) fn try_connect(stream: &mut StdTcpStream) -> io::Result<bool> {
    probe_connection(stream)
}

/// Without socket polling, fall back to a zero-length read. It can block a
/// blocking socket and report readiness without data.
pub(crate) fn is_readable(mut stream: &StdTcpStream) -> io::Result<()> {
    stream.read(&mut []).map(|_| ())
}

/// Without socket polling, fall back to a zero-length write, which cannot
/// detect a full send buffer.
pub(crate) fn is_writable(stream: &StdTcpStream) -> io::Result<()> {
    write_probe(stream)
}
