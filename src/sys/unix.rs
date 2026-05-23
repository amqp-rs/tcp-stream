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
    #[allow(unsafe_code)]
    unsafe fn from_raw_fd(fd: RawFd) -> Self {
        // SAFETY: The caller guarantees `fd` is a valid, owned file descriptor,
        // which is the same contract as `StdTcpStream::from_raw_fd`.
        Self::Plain(unsafe { StdTcpStream::from_raw_fd(fd) })
    }
}
