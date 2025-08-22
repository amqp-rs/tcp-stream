use crate::TcpStream;
use std::{
    net::TcpStream as StdTcpStream,
    os::unix::io::{AsFd, AsRawFd, BorrowedFd, FromRawFd, RawFd},
};

impl AsFd for TcpStream {
    fn as_fd(&self) -> BorrowedFd<'_> {
        <StdTcpStream as AsFd>::as_fd(self)
    }
}

impl AsRawFd for TcpStream {
    fn as_raw_fd(&self) -> RawFd {
        <StdTcpStream as AsRawFd>::as_raw_fd(self)
    }
}

impl AsRawFd for &TcpStream {
    fn as_raw_fd(&self) -> RawFd {
        <StdTcpStream as AsRawFd>::as_raw_fd(self)
    }
}

impl FromRawFd for TcpStream {
    unsafe fn from_raw_fd(fd: RawFd) -> Self {
        Self::Plain(unsafe { StdTcpStream::from_raw_fd(fd) })
    }
}
