use crate::TcpStream;
use mio::net::TcpStream as MioTcpStream;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};

impl AsRawFd for TcpStream {
    fn as_raw_fd(&self) -> RawFd {
        <MioTcpStream as AsRawFd>::as_raw_fd(self)
    }
}

impl AsRawFd for &TcpStream {
    fn as_raw_fd(&self) -> RawFd {
        <MioTcpStream as AsRawFd>::as_raw_fd(self)
    }
}

impl FromRawFd for TcpStream {
    unsafe fn from_raw_fd(fd: RawFd) -> Self {
        MioTcpStream::from_raw_fd(fd).into()
    }
}
